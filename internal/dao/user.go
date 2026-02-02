package dao

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/alist-encrypt-go/internal/storage"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrInvalidPassword = errors.New("invalid password")
	ErrUserExists      = errors.New("user already exists")
)

// Argon2 parameters (OWASP recommended)
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64MB
	argon2Threads = 4
	argon2KeyLen  = 32
	saltLength    = 16
)

// User represents a user
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

// UserDAO handles user data access
type UserDAO struct {
	store *storage.Store
}

// NewUserDAO creates a new user DAO
func NewUserDAO(store *storage.Store) *UserDAO {
	return &UserDAO{store: store}
}

// hashPassword hashes a password using Argon2id (modern, secure)
func hashPassword(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Format: base64(salt):base64(hash)
	return fmt.Sprintf("%s:%s",
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(hash)), nil
}

// verifyPassword verifies a password against a hash using constant-time comparison
func verifyPassword(password, encodedHash string) bool {
	// Split by colon
	parts := splitHash(encodedHash)
	if len(parts) != 2 {
		// Try old format (plain SHA256 hex) for backward compatibility
		return verifyLegacyPassword(password, encodedHash)
	}

	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return verifyLegacyPassword(password, encodedHash)
	}

	expectedHash, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return verifyLegacyPassword(password, encodedHash)
	}

	// Compute hash with same salt
	computedHash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1
}

// splitHash splits the encoded hash by colon
func splitHash(s string) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

// verifyLegacyPassword verifies against old SHA256 format for migration
func verifyLegacyPassword(password, hash string) bool {
	computed := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(computed[:])), []byte(hash)) == 1
}

// Create creates a new user
func (d *UserDAO) Create(username, password string) error {
	// Check if user exists
	var existing User
	if err := d.store.GetJSON(storage.BucketUsers, username, &existing); err != nil {
		return err
	}
	if existing.Username != "" {
		return ErrUserExists
	}

	hash, err := hashPassword(password)
	if err != nil {
		return err
	}

	user := User{
		Username:     username,
		PasswordHash: hash,
	}
	return d.store.SetJSON(storage.BucketUsers, username, user)
}

// Validate validates user credentials
func (d *UserDAO) Validate(username, password string) error {
	var user User
	if err := d.store.GetJSON(storage.BucketUsers, username, &user); err != nil {
		return err
	}
	if user.Username == "" {
		return ErrUserNotFound
	}
	if !verifyPassword(password, user.PasswordHash) {
		return ErrInvalidPassword
	}
	return nil
}

// Get retrieves a user
func (d *UserDAO) Get(username string) (*User, error) {
	var user User
	if err := d.store.GetJSON(storage.BucketUsers, username, &user); err != nil {
		return nil, err
	}
	if user.Username == "" {
		return nil, ErrUserNotFound
	}
	return &user, nil
}

// UpdatePassword updates a user's password
func (d *UserDAO) UpdatePassword(username, newPassword string) error {
	user, err := d.Get(username)
	if err != nil {
		return err
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	user.PasswordHash = hash
	return d.store.SetJSON(storage.BucketUsers, username, user)
}

// Delete deletes a user
func (d *UserDAO) Delete(username string) error {
	return d.store.Delete(storage.BucketUsers, username)
}

// EnsureDefaultUser ensures default admin user exists
func (d *UserDAO) EnsureDefaultUser() error {
	var user User
	if err := d.store.GetJSON(storage.BucketUsers, "admin", &user); err != nil {
		return err
	}
	if user.Username == "" {
		return d.Create("admin", "123456")
	}
	return nil
}
