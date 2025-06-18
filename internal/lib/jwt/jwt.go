package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims структура для JWT токена
type Claims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// TokenPair структура для пары токенов
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// JWTService интерфейс для работы с JWT
type JWTService interface {
	GenerateTokenPair(userID uint, email, role string) (*TokenPair, error)
	ValidateAccessToken(tokenString string) (*Claims, error)
	ValidateRefreshToken(tokenString string) (*Claims, error)
	RefreshTokens(refreshToken string) (*TokenPair, error)
}

// jwtService структура, реализующая JWTService
type jwtService struct {
	accessSecret  []byte
	refreshSecret []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	issuer        string
}

// Config конфигурация для JWT сервиса
type Config struct {
	AccessSecret  string
	RefreshSecret string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
	Issuer        string
}

// NewJWTService создает новый экземпляр JWT сервиса
func NewJWTService(cfg Config) JWTService {
	return &jwtService{
		accessSecret:  []byte(cfg.AccessSecret),
		refreshSecret: []byte(cfg.RefreshSecret),
		accessExpiry:  cfg.AccessExpiry,
		refreshExpiry: cfg.RefreshExpiry,
		issuer:        cfg.Issuer,
	}
}

// GenerateTokenPair генерирует пару токенов (access и refresh)
func (j *jwtService) GenerateTokenPair(userID uint, email, role string) (*TokenPair, error) {
	now := time.Now()

	// Создание access token
	accessClaims := &Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    j.issuer,
			Subject:   "access",
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(j.accessSecret)
	if err != nil {
		return nil, err
	}

	// Создание refresh token
	refreshClaims := &Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(j.refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    j.issuer,
			Subject:   "refresh",
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(j.refreshSecret)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
	}, nil
}

// ValidateAccessToken валидирует access token
func (j *jwtService) ValidateAccessToken(tokenString string) (*Claims, error) {
	return j.validateToken(tokenString, j.accessSecret, "access")
}

// ValidateRefreshToken валидирует refresh token
func (j *jwtService) ValidateRefreshToken(tokenString string) (*Claims, error) {
	return j.validateToken(tokenString, j.refreshSecret, "refresh")
}

// validateToken общий метод для валидации токенов
func (j *jwtService) validateToken(tokenString string, secret []byte, expectedSubject string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Проверяем метод подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("неожиданный метод подписи")
		}
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("невалидный токен")
	}

	// Проверяем subject
	if claims.Subject != expectedSubject {
		return nil, errors.New("неверный тип токена")
	}

	// Проверяем issuer
	if claims.Issuer != j.issuer {
		return nil, errors.New("неверный издатель токена")
	}

	return claims, nil
}

// RefreshTokens обновляет токены используя refresh token
func (j *jwtService) RefreshTokens(refreshToken string) (*TokenPair, error) {
	claims, err := j.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	// Генерируем новую пару токенов
	return j.GenerateTokenPair(claims.UserID, claims.Email, claims.Role)
}

// ExtractTokenFromBearer извлекает токен из Bearer заголовка
func ExtractTokenFromBearer(authHeader string) (string, error) {
	const bearerPrefix = "Bearer "

	if len(authHeader) < len(bearerPrefix) {
		return "", errors.New("неверный формат заголовка авторизации")
	}

	if authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", errors.New("отсутствует Bearer префикс")
	}

	return authHeader[len(bearerPrefix):], nil
}

// DefaultConfig возвращает конфигурацию по умолчанию
func DefaultConfig() Config {
	return Config{
		AccessSecret:  "your-access-secret-key",
		RefreshSecret: "your-refresh-secret-key",
		AccessExpiry:  15 * time.Minute,   // 15 минут для access token
		RefreshExpiry: 24 * 7 * time.Hour, // 7 дней для refresh token
		Issuer:        "auth-service",
	}
}

// Дополнительные утилиты для работы с токенами

// IsTokenExpired проверяет, истек ли токен
func IsTokenExpired(claims *Claims) bool {
	return time.Now().After(claims.ExpiresAt.Time)
}

// GetTokenTTL возвращает время жизни токена в секундах
func GetTokenTTL(claims *Claims) int64 {
	if IsTokenExpired(claims) {
		return 0
	}
	return int64(claims.ExpiresAt.Time.Sub(time.Now()).Seconds())
}
