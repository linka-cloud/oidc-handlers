module go.linka.cloud/oidc-handlers

go 1.16

require (
	github.com/coreos/go-oidc/v3 v3.0.0
	github.com/google/uuid v1.1.2
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/oauth2 v0.0.0-20220822191816-0ebed06d0094
	google.golang.org/grpc v1.47.0
)

replace (
	github.com/coreos/go-oidc/v3 => github.com/linka-cloud/go-oidc/v3 v3.0.1-0.20220921095501-0c4cee77de14
	golang.org/x/oauth2 => github.com/linka-cloud/oauth2 v0.0.0-20220921100454-a3b413368e1c
)
