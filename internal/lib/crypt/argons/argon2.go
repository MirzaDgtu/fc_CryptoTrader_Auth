package argons

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("argon2: hash format is invalid")
	ErrIncompatibleVersion = errors.New("argon2: incompatible version")
	ErrSaltGeneration      = errors.New("argon2: failed to generate salt")
	ErrPasswordTooWeak     = errors.New("argon2: password is too weak")
)

// Argon2Config содержит конфигурацию для алгоритма Argon2
type Argon2Config struct {
	Memory      uint32 // Количество памяти в КБ
	Iterations  uint32 // Количество итераций
	Parallelism uint8  // Степень параллелизма
	SaltLength  uint32 // Длина соли в байтах
	KeyLength   uint32 // Длина ключа в байтах
}

// HashResult содержит результат хеширования
type HashResult struct {
	Hash      string
	Salt      []byte
	Config    *Argon2Config
	EncodedAt int64 // Unix timestamp когда был создан хеш
}

// PasswordStrength определяет силу пароля
type PasswordStrength int

const (
	Weak PasswordStrength = iota
	Medium
	Strong
	VeryStrong
)

// GetDefaultConfig возвращает безопасную конфигурацию по умолчанию
func GetDefaultConfig() *Argon2Config {
	return &Argon2Config{
		Memory:      64 * 1024, // 64 МБ
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// GetLightConfig возвращает облегченную конфигурацию для разработки/тестов
func GetLightConfig() *Argon2Config {
	return &Argon2Config{
		Memory:      16 * 1024, // 16 МБ
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// GetHeavyConfig возвращает усиленную конфигурацию для критичных систем
func GetHeavyConfig() *Argon2Config {
	return &Argon2Config{
		Memory:      128 * 1024, // 128 МБ
		Iterations:  5,
		Parallelism: 4,
		SaltLength:  32,
		KeyLength:   64,
	}
}

// ValidatePassword проверяет силу пароля
func ValidatePassword(password string) (PasswordStrength, error) {
	if len(password) < 6 {
		return Weak, ErrPasswordTooWeak
	}

	score := 0

	// Длина
	if len(password) >= 8 {
		score++
	}
	if len(password) >= 12 {
		score++
	}

	// Проверка на разные типы символов
	hasLower, hasUpper, hasDigit, hasSpecial := false, false, false, false

	for _, char := range password {
		switch {
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case char >= 32 && char <= 126: // Печатные ASCII символы
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
				hasSpecial = true
			}
		}
	}

	if hasLower {
		score++
	}
	if hasUpper {
		score++
	}
	if hasDigit {
		score++
	}
	if hasSpecial {
		score++
	}

	switch {
	case score >= 6:
		return VeryStrong, nil
	case score >= 4:
		return Strong, nil
	case score >= 2:
		return Medium, nil
	default:
		return Weak, nil
	}
}

// GenerateSecureSalt генерирует криптографически стойкую соль
func GenerateSecureSalt(length uint32) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSaltGeneration, err)
	}
	return salt, nil
}

// HashPassword хеширует пароль с использованием Argon2id
func HashPassword(password string, config *Argon2Config) (*HashResult, error) {
	if config == nil {
		config = GetDefaultConfig()
	}

	// Проверяем силу пароля
	if strength, err := ValidatePassword(password); err != nil || strength == Weak {
		return nil, ErrPasswordTooWeak
	}

	salt, err := GenerateSecureSalt(config.SaltLength)
	if err != nil {
		return nil, err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		config.Iterations,
		config.Memory,
		config.Parallelism,
		config.KeyLength,
	)

	// Кодируем в стандартный формат
	encodedHash := encodeHash(hash, salt, config)

	return &HashResult{
		Hash:   encodedHash,
		Salt:   salt,
		Config: config,
	}, nil
}

// QuickHash быстро хеширует пароль с конфигурацией по умолчанию
func QuickHash(password string) (string, error) {
	result, err := HashPassword(password, GetDefaultConfig())
	if err != nil {
		return "", err
	}
	return result.Hash, nil
}

// VerifyPassword проверяет пароль против хеша
func VerifyPassword(password, encodedHash string) (bool, error) {
	config, salt, hash, err := DecodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		config.Iterations,
		config.Memory,
		config.Parallelism,
		config.KeyLength,
	)

	// Используем постоянное время для сравнения
	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

// CompareHashAndPassword удобная функция для проверки пароля (аналог bcrypt)
func CompareHashAndPassword(hashedPassword []byte, password []byte) error {
	match, err := VerifyPassword(string(password), string(hashedPassword))
	if err != nil {
		return err
	}
	if !match {
		return errors.New("argon2: password does not match")
	}
	return nil
}

// NeedsRehash проверяет, нужно ли перехешировать пароль с новыми параметрами
func NeedsRehash(encodedHash string, config *Argon2Config) bool {
	currentConfig, _, _, err := DecodeHash(encodedHash)
	if err != nil {
		return true
	}

	return currentConfig.Memory != config.Memory ||
		currentConfig.Iterations != config.Iterations ||
		currentConfig.Parallelism != config.Parallelism ||
		currentConfig.KeyLength != config.KeyLength
}

// GetHashInfo возвращает информацию о хеше
func GetHashInfo(encodedHash string) (*Argon2Config, error) {
	config, _, _, err := DecodeHash(encodedHash)
	return config, err
}

// DecodeHash декодирует закодированный хеш и извлекает параметры
func DecodeHash(encodedHash string) (*Argon2Config, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}

	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	config := &Argon2Config{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&config.Memory, &config.Iterations, &config.Parallelism); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid salt encoding", ErrInvalidHash)
	}
	config.SaltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid hash encoding", ErrInvalidHash)
	}
	config.KeyLength = uint32(len(hash))

	return config, salt, hash, nil
}

// encodeHash кодирует хеш в стандартный формат
func encodeHash(hash, salt []byte, config *Argon2Config) string {
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, config.Memory, config.Iterations, config.Parallelism,
		b64Salt, b64Hash)
}

// EstimateHashTime примерно оценивает время хеширования (для тестирования производительности)
func EstimateHashTime(config *Argon2Config) (string, error) {
	testPassword := "test_password_123"

	// Используем облегченную версию для оценки
	lightConfig := &Argon2Config{
		Memory:      config.Memory / 10,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  config.SaltLength,
		KeyLength:   config.KeyLength,
	}

	salt, err := GenerateSecureSalt(lightConfig.SaltLength)
	if err != nil {
		return "", err
	}

	// Простая оценка (не точная)
	estimatedMs := (config.Memory / 1024) * config.Iterations

	_ = argon2.IDKey([]byte(testPassword), salt, lightConfig.Iterations,
		lightConfig.Memory, lightConfig.Parallelism, lightConfig.KeyLength)

	return fmt.Sprintf("~%dms", estimatedMs), nil
}
