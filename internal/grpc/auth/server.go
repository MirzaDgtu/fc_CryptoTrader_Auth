package authgrpc

import (
	"context"

	ssov1 "github.com/MirzaDgtu/fc_CryptoTrader/gen/go/auth"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServiceServer
	auth Auth
}

type Auth interface {
	Login(ctx context.Context,
	)
}
