/*
This file was derived from https://github.com/go-oauth2/oauth2/blob/master/example/server/server.go.
It is used mainly for testing purpose in current project.

MIT License

Copyright (c) 2016 Lyric

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/golang-jwt/jwt"

	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/go-session/session"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/example/sampleauthserver/generates"
)

const (
	PrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIN2dALnjdcZaIZg4QuA6Dw+kxiSW502kJfmBN3priIhPoAoGCCqGSM49
AwEHoUQDQgAE4pPyvrB9ghqkT1Llk0A42lixkugFd/TBdOp6wf69O9Nndnp4+HcR
s9SlG/8hjB2Hz42v4p3haKWv3uS1C6ahCQ==
-----END EC PRIVATE KEY-----`
	KeyID = `fake-key-id`
	// path string
	pathLogin     = "/login"
	pathAuth      = "/auth"
	pathAuthorize = "/authorize"
	pathToken     = "/token"
	pathTest      = "/test"
	// http string
	httpPost     = "POST"
	httpLocation = "Location"
	// const string
	constErr            = "error: "
	constTest           = "test"
	constReturnUri      = "ReturnUri"
	constLoggedInUserID = "LoggedInUserID"
)

var (
	dumpvar   bool
	idvar     string
	secretvar string
	domainvar string
	portvar   int
)

func init() {
	flag.BoolVar(&dumpvar, "d", true, "Dump requests and responses")
	flag.StringVar(&idvar, "i", "234234", "The client id being passed in")
	flag.StringVar(&secretvar, "s", "23452345", "The client secret being passed in")
	flag.StringVar(&domainvar, "r", "http://localhost:5094", "The domain of the redirect url")
	flag.IntVar(&portvar, "p", 5096, "the base port for the server")
}

func createManager() *manage.Manager {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate(KeyID, []byte(PrivateKey), jwt.SigningMethodES256))

	clientStore := store.NewClientStore()
	clientStore.Set(idvar, &models.Client{
		ID:     idvar,
		Secret: secretvar,
		Domain: domainvar,
	})
	manager.MapClientStorage(clientStore)

	return manager
}

func createServer(manager *manage.Manager) *server.Server {
	srv := server.NewServer(server.NewConfig(), manager)

	srv.SetPasswordAuthorizationHandler(func(username, password string) (userID string, err error) {
		if username == constTest && password == constTest {
			userID = constTest
		}
		return
	})

	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println(constErr, err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println(constErr, re.Error.Error())
	})

	return srv
}

func registerHTTPHandlers(srv *server.Server) {
	http.HandleFunc(pathLogin, loginHandler)
	http.HandleFunc(pathAuth, authHandler)
	registerAuthorizeHandler(srv)
	registerTokenHandler(srv)
	registerTestHandler(srv)
}

func registerAuthorizeHandler(srv *server.Server) {
	http.HandleFunc(pathAuthorize, func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			dumpRequest(os.Stdout, "authorize", r)
		}

		store, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var form url.Values
		if v, ok := store.Get(constReturnUri); ok {
			form = v.(url.Values)
		}
		r.Form = form

		store.Delete(constReturnUri)
		store.Save()

		err = srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})
}

func registerTokenHandler(srv *server.Server) {
	http.HandleFunc(pathToken, func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			_ = dumpRequest(os.Stdout, "token", r) // Ignore the error
		}

		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

func registerTestHandler(srv *server.Server) {
	http.HandleFunc(pathTest, func(w http.ResponseWriter, r *http.Request) {
		if dumpvar {
			_ = dumpRequest(os.Stdout, constTest, r) // Ignore the error
		}
		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data := map[string]interface{}{
			"expires_in": int64(time.Until(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn())).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(data)
	})
}

func dumpRequest(writer io.Writer, header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	writer.Write([]byte("\n" + header + ": \n"))
	writer.Write(data)
	return nil
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "userAuthorizeHandler", r) // Ignore the error
	}
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		return
	}

	uid, ok := store.Get(constLoggedInUserID)
	if !ok {
		if r.Form == nil {
			r.ParseForm()
		}

		store.Set(constReturnUri, r.Form)
		store.Save()

		w.Header().Set(httpLocation, pathLogin)
		w.WriteHeader(http.StatusFound)
		return
	}

	userID = uid.(string)
	store.Delete(constLoggedInUserID)
	store.Save()
	return
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "login", r) // Ignore the error
	}
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.Method == httpPost {
		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		store.Set(constLoggedInUserID, r.Form.Get("username"))
		store.Save()

		w.Header().Set(httpLocation, pathAuth)
		w.WriteHeader(http.StatusFound)
		return
	}
	outputHTML(w, r, "static/login.html")
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if dumpvar {
		_ = dumpRequest(os.Stdout, "auth", r) // Ignore the error
	}
	store, err := session.Start(context.TODO(), w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := store.Get(constLoggedInUserID); !ok {
		w.Header().Set(httpLocation, pathLogin)
		w.WriteHeader(http.StatusFound)
		return
	}

	outputHTML(w, r, "static/auth.html")
}

func outputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
}

func main() {
	flag.Parse()
	if dumpvar {
		log.Println("Dumping requests")
	}
	manager := createManager()
	srv := createServer(manager)
	registerHTTPHandlers(srv)

	log.Printf("Server is running at %d port.\n", portvar)
	log.Printf("Point your OAuth client Auth endpoint to %s:%d%s", "http://localhost", portvar, pathAuthorize)
	log.Printf("Point your OAuth client Token endpoint to %s:%d%s", "http://localhost", portvar, pathToken)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", portvar), nil))
}
