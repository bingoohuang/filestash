package ctrl

import (
	"encoding/json"
	"fmt"
	. "github.com/bingoohuang/filestash/server/common"
	"github.com/bingoohuang/filestash/server/model"
	"github.com/gorilla/mux"
	"net/http"
	"time"
)

type Session struct {
	Home   *string `json:"home,omitempty"`
	IsAuth bool    `json:"is_authenticated"`
}

func SessionGet(ctx App, res http.ResponseWriter, req *http.Request) {
	r := Session{
		IsAuth: false,
	}

	if ctx.Backend == nil {
		SendSuccessResult(res, r)
		return
	}
	home, err := model.GetHome(ctx.Backend, ctx.Session["path"])
	if err != nil {
		SendSuccessResult(res, r)
		return
	}
	r.IsAuth = true
	r.Home = NewString(home)
	SendSuccessResult(res, r)
}

func SessionAuthenticate(ctx App, res http.ResponseWriter, req *http.Request) {
	ctx.Body["timestamp"] = time.Now().String()
	session := model.MapStringInterfaceToMapStringString(ctx.Body)
	session["path"] = EnforceDirectory(session["path"])

	backend, err := model.NewBackend(&ctx, session)
	if err != nil {
		SendErrorResult(res, err)
		return
	}

	if obj, ok := backend.(interface {
		OAuthToken(*map[string]interface{}) error
	}); ok {
		err := obj.OAuthToken(&ctx.Body)
		if err != nil {
			SendErrorResult(res, NewError("Can't authenticate (OAuth error)", 401))
			return
		}
		session = model.MapStringInterfaceToMapStringString(ctx.Body)
		backend, err = model.NewBackend(&ctx, session)
		if err != nil {
			SendErrorResult(res, NewError("Can't authenticate", 401))
			return
		}
	}

	home, err := model.GetHome(backend, session["path"])
	if err != nil {
		SendErrorResult(res, ErrAuthenticationFailed)
		return
	}

	s, err := json.Marshal(session)
	if err != nil {
		SendErrorResult(res, NewError(err.Error(), 500))
		return
	}
	obfuscate, err := EncryptString(SecretKeyDerivateForUser, string(s))
	if err != nil {
		SendErrorResult(res, NewError(err.Error(), 500))
		return
	}
	http.SetCookie(res, &http.Cookie{
		Name:     CookieNameAuth,
		Value:    obfuscate,
		MaxAge:   60 * 60 * 24 * 30,
		Path:     CookiePath,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	if home != "" {
		SendSuccessResult(res, home)
		return
	}
	SendSuccessResult(res, nil)
}

func SessionLogout(ctx App, res http.ResponseWriter, req *http.Request) {
	if ctx.Backend != nil {
		if obj, ok := ctx.Backend.(interface{ Close() error }); ok {
			go obj.Close()
		}
	}
	http.SetCookie(res, &http.Cookie{
		Name:   CookieNameAuth,
		Value:  "",
		MaxAge: -1,
		Path:   CookiePath,
	})
	http.SetCookie(res, &http.Cookie{
		Name:   CookieNameAdmin,
		Value:  "",
		MaxAge: -1,
		Path:   CookiePathAdmin,
	})
	http.SetCookie(res, &http.Cookie{
		Name:   CookieNameProof,
		Value:  "",
		MaxAge: -1,
		Path:   CookiePath,
	})
	SendSuccessResult(res, nil)
}

func SessionOAuthBackend(ctx App, res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	a := map[string]string{
		"type": vars["service"],
	}
	b, err := model.NewBackend(&ctx, a)
	if err != nil {
		SendErrorResult(res, err)
		return
	}
	obj, ok := b.(interface{ OAuthURL() string })
	if !ok {
		SendErrorResult(res, NewError(fmt.Sprintf("This backend doesn't support oauth: '%s'", a["type"]), 500))
		return
	}
	SendSuccessResult(res, obj.OAuthURL())
}
