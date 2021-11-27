/*
This file was derived from https://github.com/go-oauth2/oauth2/blob/master/example/client/client.go
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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	authServerURL = "http://localhost:5096"
	rasServerURL  = "http://localhost:40002"
)

var (
	config = oauth2.Config{
		ClientID:     "234234",
		ClientSecret: "23452345",
		Scopes:       []string{"write:config"},
		RedirectURL:  "http://localhost:5094/oauth2",
		Endpoint: oauth2.Endpoint{
			AuthURL:  authServerURL + "/authorize",
			TokenURL: authServerURL + "/token",
		},
	}
	globalToken *oauth2.Token
)

func authHandler(w http.ResponseWriter, r *http.Request) {
	url := config.AuthCodeURL("abc",
		oauth2.SetAuthURLParam("code_challenge", genCodeChallengeS256("s256example")),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	http.Redirect(w, r, url, http.StatusFound)
}

func oauth2Handler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	state := r.Form.Get("state")
	if state != "abc" {
		http.Error(w, "State invalid", http.StatusBadRequest)
		return
	}
	code := r.Form.Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}
	token, err := config.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", "s256example"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	globalToken = token

	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(token)
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	if globalToken == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	globalToken.Expiry = time.Now()
	token, err := config.TokenSource(context.Background(), globalToken).Token()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	globalToken = token
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(token)
}

func AddAuthReqEditor(jws string) restapi.RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+jws)
		return ctx.Err()
	}
}

func CreateClient(w http.ResponseWriter) {
	c, _ := restapi.NewClientWithResponses(rasServerURL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	name := "version"
	value := "0.1.0"
	body := restapi.PostConfigJSONRequestBody{{Name: &name, Value: &value}}
	configResponse, err := c.GetConfigWithResponse(ctx)
	if err != nil || http.StatusOK != configResponse.StatusCode() {
		http.Error(w, "failed to get config", http.StatusInternalServerError)
		return
	}

	configResponse1, err := c.PostConfigWithResponse(ctx, body, AddAuthReqEditor(globalToken.AccessToken))
	if err != nil || http.StatusOK != configResponse1.StatusCode() {
		http.Error(w, "failed to post config", http.StatusInternalServerError)
		return
	}

	io.Copy(w, strings.NewReader("got it!"))
}

func tryHandler(w http.ResponseWriter, r *http.Request) {
	if globalToken == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	CreateClient(w)
}

func pwdHandler(w http.ResponseWriter, r *http.Request) {
	_ = r
	token, err := config.PasswordCredentialsToken(context.Background(), "test", "test")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	globalToken = token
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(token)
}

func clientHandler(w http.ResponseWriter, r *http.Request) {
	_ = r
	cfg := clientcredentials.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		TokenURL:     config.Endpoint.TokenURL,
	}

	token, err := cfg.Token(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(token)
}

func genCodeChallengeS256(s string) string {
	s256 := sha256.Sum256([]byte(s))
	return base64.URLEncoding.EncodeToString(s256[:])
}

func main() {
	http.HandleFunc("/", authHandler)

	http.HandleFunc("/oauth2", oauth2Handler)

	http.HandleFunc("/refresh", refreshHandler)

	http.HandleFunc("/try", tryHandler)

	http.HandleFunc("/pwd", pwdHandler)

	http.HandleFunc("/client", clientHandler)

	log.Println("Client is running. Please open http://localhost:5094")
	log.Fatal(http.ListenAndServe(":5094", nil))
}
