package service

import (
	"testjunior/internal/model"
	"testjunior/internal/repository"
)

type Authorization interface {
	CreateUser(user model.User) (int, error)
	GenerateToken(username, password string) (string, error)
	GenerateTokenPair(userID int, userAgent, ip string) (access, refresh string, err error)
	RefreshTokenPair(refreshToken, userAgent, ip string) (access, refresh string, err error)
	ParseToken(token string) (int, error)
	GetAllActiveRefreshTokens() ([]model.RefreshToken, error)
	DeactivateRefreshToken(id int) error
	DeactivateRefreshTokenByValue(refreshToken string) error
}

type Service struct {
	Authorization
}

func NewService(repos *repository.Repository) *Service {
	return &Service{
		Authorization: NewAuthService(repos.Authorization),
	}
}
