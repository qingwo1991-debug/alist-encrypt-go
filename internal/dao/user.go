package dao

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/alist-encrypt-go/internal/storage"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrInvalidPassword = errors.New("invalid password")
	ErrUserExists      = errors.New("user already exists")
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

// hashPassword hashes a password using SHA256
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
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

	user := User{
		Username:     username,
		PasswordHash: hashPassword(password),
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
	if user.PasswordHash != hashPassword(password) {
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
	user.PasswordHash = hashPassword(newPassword)
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
		return d.Create("admin", "admin")
	}
	return nil
}
