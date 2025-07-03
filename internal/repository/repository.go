package repository

import (
	"testjunior/internal/model"

	"github.com/jmoiron/sqlx"
)

type Authorization interface {
	CreateUser(user model.User) (int, error)
	GetUser(username, password string) (model.User, error)
	CreateRefreshToken(userID int, tokenHash, userAgent, ip string) error
	GetActiveRefreshToken(userID int) (model.RefreshToken, error)
	DeactivateRefreshToken(tokenID int) error
	GetRefreshTokenByHash(tokenHash string) (model.RefreshToken, error)
	GetAllActiveRefreshTokens() ([]model.RefreshToken, error)
}

type Repository struct {
	Authorization
}

func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{
		Authorization: NewAuthPostgres(db),
	}
}
