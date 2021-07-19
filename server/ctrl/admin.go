package ctrl

import (
	"encoding/json"
	. "github.com/bingoohuang/filestash/server/common"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"time"
)

func AdminSessionGet(_ App, res http.ResponseWriter, req *http.Request) {
	if admin := ConfigAuthAdmin(); admin == "" {
		SendSuccessResult(res, true)
		return
	}
	obfuscate := func() string {
		c, err := req.Cookie(CookieNameAdmin)
		if err != nil {
			return ""
		}
		return c.Value
	}()

	str, err := DecryptString(SecretKeyDerivateForAdmin, obfuscate)
	if err != nil {
		SendSuccessResult(res, false)
		return
	}
	token := AdminToken{}
	json.Unmarshal([]byte(str), &token)

	if !token.IsValid() {
		SendSuccessResult(res, false)
		return
	} else if !token.IsAdmin() {
		SendSuccessResult(res, false)
		return
	}
	SendSuccessResult(res, true)
}

func AdminSessionAuthenticate(ctx App, res http.ResponseWriter, req *http.Request) {
	// Step 1: Deliberatly make the request slower to make hacking attempt harder for the attacker
	time.Sleep(1500 * time.Millisecond)

	// Step 2: Make sure current user has appropriate access
	admin := ConfigAuthAdmin()
	if admin == "" {
		SendErrorResult(res, NewError("Missing admin account, please contact your administrator", 500))
		return
	}
	var params map[string]string
	b, _ := ioutil.ReadAll(req.Body)
	json.Unmarshal(b, &params)
	if err := bcrypt.CompareHashAndPassword([]byte(admin), []byte(params["password"])); err != nil {
		SendErrorResult(res, ErrInvalidPassword)
		return
	}

	// Step 3: Send response to the client
	body, _ := json.Marshal(NewAdminToken())
	obfuscate, err := EncryptString(SecretKeyDerivateForAdmin, string(body))
	if err != nil {
		SendErrorResult(res, err)
		return
	}
	http.SetCookie(res, &http.Cookie{
		Name:     CookieNameAdmin,
		Value:    obfuscate,
		Path:     CookiePathAdmin,
		MaxAge:   60 * 60, // valid for 1 hour
		SameSite: http.SameSiteStrictMode,
	})
	SendSuccessResult(res, true)
}

func AdminBackend(ctx App, res http.ResponseWriter, req *http.Request) {
	drivers := Backend.Drivers()
	backends := make(map[string]Form, len(drivers))
	for key := range drivers {
		backends[key] = drivers[key].LoginForm()
	}
	SendSuccessResultWithEtagAndGzip(res, req, backends)
	return
}
