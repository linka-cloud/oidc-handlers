# OIDC Http Handlers

A set of handlers to easily implements OIDC auth in applications.

### Getting Started

A [docker-compose.yml](docker-compose.yml) is available for testing:

```bash
docker-compose up -d
```

[Example App](example-test/example.go):

```go
package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/sirupsen/logrus"

	oidc_handlers "gitlab.bertha.cloud/partitio/lab/oidc-hanlers"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := oidc_handlers.Config{
		IssuerURL:     "http://localhost:5556",
		ClientID:      "oidc",
		ClientSecret:  "0TJ3992YlriTfyuTgcO81L8b6eZWlWwKC2Gqij5nR44",
		OauthCallback: "http://example.localhost:8888/auth/callback",
		Logger:        logrus.New(),
	}
	oidc, err := oidc_handlers.New(ctx, config)
	if err != nil {
		logrus.Fatal(err)
	}
	http.HandleFunc("/auth", oidc.RedirectHandler)
	http.HandleFunc("/auth/callback", oidc.CallbackHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := oidc.Refresh(w, r); err != nil {
			logrus.Error(err)
			oidc.SetRedirectCookie(w, "/")
			http.Redirect(w, r, "/auth", http.StatusSeeOther)
			return
		}
		c, ok := oidc_handlers.ClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "no claims found", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(c)
	})
	if err := http.ListenAndServe(":8888", nil); err != nil {
		logrus.Fatal(err)
	}
}

```

Application is available at [http://example.localhost:8888]
**Email**: admin@example.com
**Password**: password
