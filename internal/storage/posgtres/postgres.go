package storage

import (
	"database/sql"
	"fc_cryptotrader_auth/internal/domain/models"
	"fc_cryptotrader_auth/internal/storage"

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
	query := `INSERT INTO users (username, email, password, phone, first_name, last_name, middle_name)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`
	err := s.db.QueryRow(query, username, email,
		password, phone, first_name, lastname, middle_name).Scan(&userID)

	if err != nil {
		if err == sql.ErrNoRows {
			return 0, storage.ErrUserExists
		}
		return 0, err
	}

	return userID, nil

}

func (s *Storage) Login(email string, password string) (user models.User, token string, err error) {
	query := `SELECT * FROM users WHERE email = $1 AND password = $2`
	err := s.db.QueryRow(query, email, password).Scan(&user.Id, &user.Username, &user.Email,
		&user.Phone, &user.FirstName, &user.LastName, &user.MiddleName, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return models.User{}, "", storage.ErrInvalidCredentials
		}
		return models.User{}, "", err
	}

	return user, "", nil
}
