module go.linka.cloud/oidc-handlers

go 1.16

require (
	github.com/coreos/go-oidc/v3 v3.0.0
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/oauth2 v0.0.0-20210402161424-2e8d93401602
	google.golang.org/grpc v1.40.0 // indirect
)

replace (
	github.com/coreos/go-oidc/v3 => github.com/linka-cloud/go-oidc/v3 v3.0.0-lk
	golang.org/x/oauth2 => github.com/linka-cloud/oauth2 v1.0.0-lk
)
