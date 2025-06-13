package authgrpc

import (
	"context"
	"errors"
	"fc_cryptotrader_auth/internal/storage"

	authpb "github.com/MirzaDgtu/fcCryptoTrader/generated/go/auth"
	commonpb "github.com/MirzaDgtu/fcCryptoTrader/generated/go/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type serverAPI struct {
	authpb.UnimplementedAuthServer
	auth Auth
}

type Auth interface {
	Register(ctx context.Context,
		username string,
		email string,
		password string,
		phone string,
		first_name string,
		lastname string,
		middle_name string) (*authpb.RegisterResponse, error)
	Login(ctx context.Context,
		email string,
		password string) (*authpb.LoginResponse, error)
	Logout(ctx context.Context,
		sessionID string,
		token string) (*authpb.LogoutResponse, error)
	RefreshToken(ctx context.Context,
		refresh_token string) (*authpb.RefreshTokenResponse, error)
	ValidateToken(ctx context.Context,
		token string) (*authpb.ValidateTokenResponse, error)
	ChangePassword(ctx context.Context,
		user_id string,
		current_password string,
		new_password string) (*authpb.ChangePasswordResponse, error)
	ResetPassword(ctx context.Context,
		email string) (*authpb.ResetPasswordResponse, error)
	ConfirmResetPassword(ctx context.Context,
		token string,
		new_password string) (*authpb.ConfirmResetPasswordResponse, error)
	HealthCheck(ctx context.Context, service string) (*commonpb.HealthCheckResponse, error)
}

func (s *serverAPI) Register(ctx context.Context, req *authpb.RegisterRequest) (*authpb.RegisterResponse, error) {
	user, err := s.auth.Register(ctx, req.Username, req.Email, req.Password, req.Phone, req.FirstName, req.LastName, req.MiddleName)

	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "failed to register user")
	}

	return &authpb.RegisterResponse{
		User: user,
	}, err
}

func (s *serverAPI) Login(ctx context.Context, req *authpb.LoginRequest) (*authpb.LoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password must be provided")
	}

	if len(req.Password) < 8 {
		return nil, status.Error(codes.InvalidArgument, "password must be at least 8 characters long")
	}
	if len(req.Email) < 5 || len(req.Email) > 254 {
		return nil, status.Error(codes.InvalidArgument, "email must be between 5 and 254 characters long")
	}

	if !storage.IsValidEmail(req.Email) {
		return nil, status.Error(codes.InvalidArgument, "invalid email format")
	}

	token, err := s.auth.Login(ctx, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		if errors.Is(err, storage.ErrInvalidCredentials) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "failed to login user")
	}

	return &authpb.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverAPI) Logout(ctx context.Context, req *authpb.LogoutRequest) (*authpb.LogoutResponse, error) {
	if req.SessionId == "" || req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "session ID and token must be provided")
	}
	if len(req.SessionId) < 1 || len(req.SessionId) > 64 {
		return nil, status.Error(codes.InvalidArgument, "session ID must be between 1 and 64 characters long")
	}
	if len(req.Token) < 1 || len(req.Token) > 256 {
		return nil, status.Error(codes.InvalidArgument, "token must be between 1 and 256 characters long")
	}

	res, err := s.auth.Logout(ctx, req.SessionId, req.Token)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		if errors.Is(err, storage.ErrInvalidCredentials) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "failed to logout user")
	}
	if res == nil {
		return nil, status.Error(codes.Internal, "logout response is nil")
	}

	return &authpb.LogoutResponse{
		Success: true,
	}, nil
}

func (s *serverAPI) RefreshToken(ctx context.Context, req *authpb.RefreshTokenRequest) (*authpb.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token must be provided")
	}
	if len(req.RefreshToken) < 1 || len(req.RefreshToken) > 256 {
		return nil, status.Error(codes.InvalidArgument, "refresh token must be between 1 and 256 characters long")
	}

	token, err := s.auth.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidCredentials) {
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		}
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
	}

	return &authpb.RefreshTokenResponse{
		Token: token,
	}, nil

}

func (s *serverAPI) ValidateToken(ctx context.Context, req *authpb.ValidateTokenRequest) (*authpb.ValidateTokenResponse, error) {
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token must be provided")
	}
	if len(req.Token) < 1 || len(req.Token) > 256 {
		return nil, status.Error(codes.InvalidArgument, "token must be between 1 and 256 characters long")
	}

	token, err := s.auth.ValidateToken(ctx, req.Token)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidCredentials) {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to validate token")
	}
	if token == nil {
		return nil, status.Error(codes.Unauthenticated, "token is invalid or expired")
	}
	if token.UserId == "" {
		return nil, status.Error(codes.Unauthenticated, "token does not contain user ID")
	}
	if token.ExpiresAt == 0 {
		return nil, status.Error(codes.Unauthenticated, "token does not contain expiration time")
	}
	if token.IssuedAt == 0 {
		return nil, status.Error(codes.Unauthenticated, "token does not contain issued time")
	}

	return &authpb.ValidateTokenResponse{
		UserId:    token.UserId,
		ExpiresAt: token.ExpiresAt,
		IssuedAt:  token.IssuedAt,
	}, nil
}

func (s *serverAPI) ChangePassword(ctx context.Context, req *authpb.ChangePasswordRequest) (*authpb.ChangePasswordResponse, error) {
	return s.auth.ChangePassword(ctx, req.UserId, req.CurrentPassword, req.NewPassword)
}

func (s *serverAPI) ResetPassword(ctx context.Context, req *authpb.ResetPasswordRequest) (*authpb.ResetPasswordResponse, error) {
	return s.auth.ResetPassword(ctx, req.Email)
}

func (s *serverAPI) ConfirmResetPassword(ctx context.Context, req *authpb.ConfirmResetPasswordRequest) (*authpb.ConfirmResetPasswordResponse, error) {
	return s.auth.ConfirmResetPassword(ctx, req.Token, req.NewPassword)
}

func (s *serverAPI) HealthCheck(ctx context.Context, req *commonpb.HealthCheckRequest) (*commonpb.HealthCheckResponse, error) {
	return s.auth.HealthCheck(ctx, req.Service)
}
