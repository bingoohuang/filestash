package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	. "github.com/bingoohuang/filestash/server/common"
	"github.com/bingoohuang/filestash/server/model"
	"github.com/gorilla/mux"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

func LoggedInOnly(fn func(App, http.ResponseWriter, *http.Request)) func(ctx App, res http.ResponseWriter, req *http.Request) {
	return func(ctx App, res http.ResponseWriter, req *http.Request) {
		if ctx.Backend == nil || ctx.Session == nil {
			SendErrorResult(res, ErrPermissionDenied)
			return
		}
		fn(ctx, res, req)
	}
}

func AdminOnly(fn func(App, http.ResponseWriter, *http.Request)) func(ctx App, res http.ResponseWriter, req *http.Request) {
	return func(ctx App, res http.ResponseWriter, req *http.Request) {
		if admin := ConfigAuthAdmin(); admin != "" {
			c, err := req.Cookie(CookieNameAdmin)
			if err != nil {
				SendErrorResult(res, ErrPermissionDenied)
				return
			}

			str, err := DecryptString(SecretKeyDerivateForAdmin, c.Value)
			if err != nil {
				SendErrorResult(res, ErrPermissionDenied)
				return
			}
			token := AdminToken{}
			json.Unmarshal([]byte(str), &token)

			if !token.IsValid() || !token.IsAdmin() {
				SendErrorResult(res, ErrPermissionDenied)
				return
			}
		}
		fn(ctx, res, req)
	}
}

func SessionStart(fn func(App, http.ResponseWriter, *http.Request)) func(ctx App, res http.ResponseWriter, req *http.Request) {
	return func(ctx App, res http.ResponseWriter, req *http.Request) {
		var err error
		if ctx.Share, err = _extractShare(req); err != nil {
			SendErrorResult(res, err)
			return
		}
		if ctx.Session, err = _extractSession(req, &ctx); err != nil {
			SendErrorResult(res, err)
			return
		}
		if ctx.Backend, err = _extractBackend(req, &ctx); err != nil {
			if len(ctx.Session) == 0 {
				SendErrorResult(res, ErrNotAuthorized)
				return
			}
			SendErrorResult(res, err)
			return
		}
		fn(ctx, res, req)
	}
}

func SessionTry(fn func(App, http.ResponseWriter, *http.Request)) func(ctx App, res http.ResponseWriter, req *http.Request) {
	return func(ctx App, res http.ResponseWriter, req *http.Request) {
		ctx.Share, _ = _extractShare(req)
		ctx.Session, _ = _extractSession(req, &ctx)
		ctx.Backend, _ = _extractBackend(req, &ctx)
		fn(ctx, res, req)
	}
}

func RedirectSharedLoginIfNeeded(fn func(App, http.ResponseWriter, *http.Request)) func(ctx App, res http.ResponseWriter, req *http.Request) {
	return func(ctx App, res http.ResponseWriter, req *http.Request) {
		share_id := _extractShareId(req)
		if share_id == "" {
			if mux.Vars(req)["share"] == "private" {
				fn(ctx, res, req)
				return
			}
			SendErrorResult(res, ErrNotValid)
			return
		}

		share, err := _extractShare(req)
		if err != nil || share_id != share.Id {
			http.Redirect(res, req, fmt.Sprintf("/s/%s?next=%s", share_id, req.URL.Path), http.StatusTemporaryRedirect)
			return
		}
		fn(ctx, res, req)
	}
}

func CanManageShare(fn func(App, http.ResponseWriter, *http.Request)) func(ctx App, res http.ResponseWriter, req *http.Request) {
	return func(ctx App, res http.ResponseWriter, req *http.Request) {
		share_id := mux.Vars(req)["share"]
		if share_id == "" {
			SendErrorResult(res, ErrNotValid)
			return
		}

		// anyone can manage a share_id that's not been attributed yet
		s, err := model.ShareGet(share_id)
		if err != nil {
			if err == ErrNotFound {
				SessionStart(fn)(ctx, res, req)
				return
			}
			SendErrorResult(res, err)
			return
		}

		// In a scenario where the shared link has already been atributed, we need to make sure
		// the user that's currently logged in can manage the link. 2 scenarios here:
		// 1) scenario 1: the user is the very same one that generated the shared link in the first place
		ctx.Share = Share{}
		if ctx.Session, err = _extractSession(req, &ctx); err != nil {
			SendErrorResult(res, err)
			return
		}
		if s.Backend == GenerateID(&ctx) {
			fn(ctx, res, req)
			return
		}
		// 2) scenario 2: the user is different than the one that has generated the shared link
		// in this scenario, the link owner might have granted for user the right to reshare links
		if ctx.Share, err = _extractShare(req); err != nil {
			SendErrorResult(res, err)
			return
		}
		if ctx.Session, err = _extractSession(req, &ctx); err != nil {
			SendErrorResult(res, err)
			return
		}

		if s.Backend == GenerateID(&ctx) {
			if s.CanShare {
				fn(ctx, res, req)
				return
			}
		}
		SendErrorResult(res, ErrPermissionDenied)
		return
	}
}

func _extractShareId(req *http.Request) string {
	share := req.URL.Query().Get("share")
	if share != "" {
		return share
	}
	m := mux.Vars(req)["share"]
	if m == "private" {
		return ""
	}
	return m
}

func _extractShare(req *http.Request) (Share, error) {
	var err error
	share_id := _extractShareId(req)
	if share_id == "" {
		return Share{}, nil
	}
	if !Config.Get("features.share.enable").Bool() {
		Log.Debug("Share feature isn't enable, contact your administrator")
		return Share{}, NewError("Feature isn't enable, contact your administrator", 405)
	}

	s, err := model.ShareGet(share_id)
	if err != nil {
		return Share{}, nil
	}
	if err = s.IsValid(); err != nil {
		return Share{}, err
	}

	var verifiedProof = model.ShareProofGetAlreadyVerified(req)
	username, password := func(authHeader string) (string, string) {
		decoded, err := base64.StdEncoding.DecodeString(
			strings.TrimPrefix(authHeader, "Basic "),
		)
		if err != nil {
			return "", ""
		}
		s := bytes.Split(decoded, []byte(":"))
		if len(s) < 2 {
			return "", ""
		}
		p := string(bytes.Join(s[1:], []byte(":")))
		usr := regexp.MustCompile(`^(.*)\[([0-9a-zA-Z]+)\]$`).FindStringSubmatch(string(s[0]))
		if len(usr) != 3 {
			return "", p
		}
		if Hash(usr[1]+SecretKeyDerivateForHash, 10) != usr[2] {
			return "", p
		}
		return usr[1], p
	}(req.Header.Get("Authorization"))

	if s.Users != nil && username != "" {
		if v, ok := model.ShareProofVerifierEmail(*s.Users, username); ok {
			verifiedProof = append(verifiedProof, model.Proof{Key: "email", Value: v})
		}
	}
	if s.Password != nil && password != "" {
		if v, ok := model.ShareProofVerifierPassword(*s.Password, password); ok {
			verifiedProof = append(verifiedProof, model.Proof{Key: "password", Value: v})
		}
	}
	var requiredProof = model.ShareProofGetRequired(s)
	var remainingProof = model.ShareProofCalculateRemainings(requiredProof, verifiedProof)
	if len(remainingProof) != 0 {
		return Share{}, NewError("Unauthorized Shared space", 400)
	}
	return s, nil
}

type SftpConfig struct {
	Hostname  string    `json:"hostname"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
}

func (s SftpConfig) SetSession() {
	// {"hostkey":"","hostname":"192.168.126.71","passphrase":"","password":"12354678","path":"/","port":"","timestamp":"2021-07-19 15:30:33.374809 +0800 CST m=+40.464059475","type":"sftp","username":"root"}
	s.Type = "sftp"
	jso, _ := json.Marshal(s)
	var session = make(map[string]string)
	json.Unmarshal(jso, &session)

	SetGlobalSession(session)
}

func GetGlobalSession() map[string]string {
	GlobalSessionLock.Lock()
	defer GlobalSessionLock.Unlock()

	return GlobalSession
}

func SetGlobalSession(s map[string]string) {
	GlobalSessionLock.Lock()
	GlobalSession = s
	GlobalSessionLock.Unlock()
}

var GlobalSessionLock sync.Mutex
var GlobalSession map[string]string

func _extractSession(req *http.Request, ctx *App) (map[string]string, error) {
	var str string
	var err error
	var session = make(map[string]string)

	if ctx.Share.Id != "" {
		str, err = DecryptString(SecretKeyDerivateForUser, ctx.Share.Auth)
		if err != nil {
			// This typically happen when changing the secret key
			return session, nil
		}
		err = json.Unmarshal([]byte(str), &session)
		if IsDirectory(ctx.Share.Path) {
			session["path"] = ctx.Share.Path
		} else {
			// when the shared link is pointing to a file, we mustn't have access to the surroundings
			// => we need to take extra care of which path to use as a chroot
			var path = req.URL.Query().Get("path")
			if strings.HasPrefix(req.URL.Path, "/api/export/") {
				var re = regexp.MustCompile(`^/api/export/[^\/]+/[^\/]+/[^\/]+(\/.+)$`)
				path = re.ReplaceAllString(req.URL.Path, `$1`)
			}
			if !strings.HasSuffix(ctx.Share.Path, path) {
				return make(map[string]string), ErrPermissionDenied
			}
			session["path"] = strings.TrimSuffix(ctx.Share.Path, path) + "/"
		}
		return session, err
	}

	s := GetGlobalSession()
	if s != nil {
		return s, nil
	}

	cookie, err := req.Cookie(CookieNameAuth)
	if err != nil {
		return session, nil
	}
	str = cookie.Value
	str, err = DecryptString(SecretKeyDerivateForUser, str)
	if err != nil {
		// This typically happen when changing the secret key
		return session, nil
	}
	err = json.Unmarshal([]byte(str), &session)
	return session, err
}

func _extractBackend(req *http.Request, ctx *App) (IBackend, error) {
	return model.NewBackend(ctx, ctx.Session)
}
