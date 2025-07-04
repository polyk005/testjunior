package service

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"testjunior/internal/model"
	"testjunior/internal/repository"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

const (
	salt               = "generate_hash_code"
	signingKey         = "generate_hash_code"
	tokenTTL           = 24 * time.Hour
	refreshTokenLength = 32
	webhookURL         = "http://webhook-url" // заменить на реальный URL
)

type TokenClaims struct {
	jwt.StandardClaims
	UserId int `json:"user_id"`
}

type AuthService struct {
	repo repository.Authorization
}

func NewAuthService(repo repository.Authorization) *AuthService {
	return &AuthService{repo: repo}
}

func (s *AuthService) CreateUser(user model.User) (int, error) {
	user.Password = s.generatePasswordHash(user.Password)
	return s.repo.CreateUser(user)
}

func (s *AuthService) GenerateToken(username, password string) (string, error) {
	user, err := s.repo.GetUser(username, s.generatePasswordHash(password))
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &TokenClaims{
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(tokenTTL).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		user.Id,
	})
	return token.SignedString([]byte(signingKey))
}

func (s *AuthService) generatePasswordHash(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))

	return fmt.Sprintf("%x", hash.Sum([]byte(salt)))
}

func (s *AuthService) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func (s *AuthService) ParseToken(accesstoken string) (int, error) {
	token, err := jwt.ParseWithClaims(accesstoken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(signingKey), nil
	})
	if err != nil {
		return 0, err
	}
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return 0, errors.New("token claims are not of type *tokenClaims")
	}
	return claims.UserId, nil
}

func (s *AuthService) GenerateTokenPair(userID int, userAgent, ip string) (string, string, error) {
	// Access token (JWT SHA512)
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, &TokenClaims{
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(tokenTTL).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		userID,
	})
	accessToken, err := token.SignedString([]byte(signingKey))
	if err != nil {
		return "", "", err
	}

	refreshRaw := make([]byte, refreshTokenLength)
	_, err = rand.Read(refreshRaw)
	if err != nil {
		return "", "", err
	}
	refreshToken := base64.StdEncoding.EncodeToString(refreshRaw)
	refreshHash, err := s.HashPassword(refreshToken)
	if err != nil {
		return "", "", err
	}
	// Сохраняем refresh токен
	err = s.repo.CreateRefreshToken(userID, refreshHash, userAgent, ip)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

func (s *AuthService) RefreshTokenPair(refreshToken, userAgent, ip string) (string, string, error) {
	tokens, err := s.repo.GetAllActiveRefreshTokens()
	if err != nil {
		return "", "", err
	}
	var matchedToken *model.RefreshToken
	for _, t := range tokens {
		if bcrypt.CompareHashAndPassword([]byte(t.TokenHash), []byte(refreshToken)) == nil {
			matchedToken = &t
			break
		}
	}
	if matchedToken == nil {
		return "", "", errors.New("invalid refresh token")
	}

	if matchedToken.UserAgent != userAgent {
		_ = s.repo.DeactivateRefreshToken(matchedToken.ID)
		return "", "", errors.New("user-agent mismatch, token deauthorized")
	}

	if matchedToken.IP != ip {
		go func() {
			_ = sendWebhook(matchedToken.UserID, ip, userAgent)
		}()
	}

	err = s.repo.DeactivateRefreshToken(matchedToken.ID)
	if err != nil {
		return "", "", err
	}

	return s.GenerateTokenPair(matchedToken.UserID, userAgent, ip)
}

func sendWebhook(userID int, ip, userAgent string) error {
	body := []byte(fmt.Sprintf(`{"user_id":%d,"ip":"%s","user_agent":"%s"}`, userID, ip, userAgent))
	_, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	return err
}

func (s *AuthService) GetAllActiveRefreshTokens() ([]model.RefreshToken, error) {
	return s.repo.GetAllActiveRefreshTokens()
}

func (s *AuthService) DeactivateRefreshToken(id int) error {
	return s.repo.DeactivateRefreshToken(id)
}

func (s *AuthService) DeactivateRefreshTokenByValue(refreshToken string) error {
	tokens, err := s.GetAllActiveRefreshTokens()
	if err != nil {
		return err
	}

	for _, t := range tokens {
		if bcrypt.CompareHashAndPassword([]byte(t.TokenHash), []byte(refreshToken)) == nil {
			return s.DeactivateRefreshToken(t.ID)
		}
	}

	return nil
}
