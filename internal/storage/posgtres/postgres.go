package storage

import (
	"database/sql"
	"fc_cryptotrader_auth/internal/domain/models"
	argons "fc_cryptotrader_auth/internal/lib/crypt"
	jwt "fc_cryptotrader_auth/internal/lib/jwt"
	"fc_cryptotrader_auth/internal/storage"
	"strconv"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

type Storage struct {
	db *sql.DB
}

func New(storagePath string) (*Storage, error) {
	db, err := sql.Open("postgres", storagePath)
	if err != nil {
		panic("failed to connect to database: " + err.Error())
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &Storage{
		db: db,
	}, nil
}

func (s *Storage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Storage) DB() *sql.DB {
	return s.db
}

func (s *Storage) Ping() error {
	if s.db == nil {
		return sql.ErrConnDone
	}
	return s.db.Ping()
}

func (s *Storage) IsConnected() bool {
	if s.db == nil {
		return false
	}
	err := s.db.Ping()
	if err != nil {
		return false
	}
	return true
}

func (s *Storage) Register(username string,
	email string,
	password string,
	phone string,
	first_name string,
	lastname string,
	middle_name string) (int64, error) {

	var userID int64
	hashedPassword, err := argons.QuickHash(password)

	if err != nil {
		return 0, err
	}

	query := `INSERT INTO users (username, email, password, phone, first_name, last_name, middle_name)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`

	err = s.db.QueryRow(query,
		username,
		email,
		hashedPassword,
		phone,
		first_name,
		lastname,
		middle_name).Scan(&userID)

	if err != nil {
		if err == sql.ErrNoRows {
			return 0, storage.ErrUserExists
		}
		return 0, err
	}

	return userID, nil

}

func (s *Storage) Login(email string, password string) (user models.User, token string, err error) {
	// Получаем пользователя по email
	query := `SELECT id, username, email, phone, first_name, last_name, middle_name, password, is_active, role, created_at, updated_at 
			  FROM users WHERE email = $1`

	err = s.db.QueryRow(query, email).Scan(&user.Id,
		&user.Username,
		&user.Email,
		&user.Phone,
		&user.FirstName,
		&user.LastName,
		&user.MiddleName,
		&user.PasswordHash, // это []byte
		&user.IsActive,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return models.User{}, "", storage.ErrInvalidCredentials
		}
		return models.User{}, "", err
	}

	// Проверяем, активен ли пользователь
	if !user.IsActive {
		return models.User{}, "", storage.ErrUserInactive // добавьте эту ошибку
	}

	// Проверяем пароль (PasswordHash это []byte, нужно преобразовать в string)
	isValidPassword, err := argons.VerifyPassword(password, string(user.PasswordHash))
	if err != nil {
		return models.User{}, "", err
	}

	if !isValidPassword {
		return models.User{}, "", storage.ErrInvalidCredentials
	}

	// Генерируем токен
	userId, err := strconv.Atoi(user.Id) // Преобразуем ID пользователя в строку
	if err != nil {
		return models.User{}, "", err
	}

	cfg := jwt.Config{
		AccessSecret:  "your_access_secret",
		RefreshSecret: "your_refresh_secret",
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 30 * 24 * time.Hour, // 30 дней
	}

	// Создаем JWT сервис
	jwtService := jwt.NewJWTService(cfg)

	// Генерируем пару токенов
	tokens, err := jwtService.GenerateTokenPair(uint(userId), user.Email, user.Role) // используем роль пользователя
	if err != nil {
		return models.User{}, "", err
	}

	// Очищаем пароль перед возвратом (безопасность)
	user.PasswordHash = nil

	return user, tokens.AccessToken, nil
}
