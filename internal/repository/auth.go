package repository

import (
	"fmt"
	"testjunior/internal/model"

	"github.com/jmoiron/sqlx"
)

type AuthPostgres struct {
	db *sqlx.DB
}

func NewAuthPostgres(db *sqlx.DB) *AuthPostgres {
	return &AuthPostgres{db: db}
}

func (r *AuthPostgres) CreateUser(user model.User) (int, error) {
	var id int

	query := fmt.Sprintf(`INSERT INTO %s (name, username, password_hash, email) VALUES ($1, $2, $3, $4) RETURNING id`, userTable)

	auth := r.db.QueryRow(query, user.Name, user.Username, user.Password, user.Email)
	if err := auth.Scan(&id); err != nil {
		return 0, err
	}

	return id, nil
}

func (r *AuthPostgres) GetUser(username, password string) (model.User, error) {
	var user model.User
	query := fmt.Sprintf("SELECT id FROM %s WHERE username=$1 AND password_hash=$2", userTable)
	err := r.db.Get(&user, query, username, password)
	return user, err
}

func (r *AuthPostgres) CreateRefreshToken(userID int, tokenHash, userAgent, ip string) error {
	query := `INSERT INTO refresh_tokens (user_id, token_hash, user_agent, ip) VALUES ($1, $2, $3, $4)`
	_, err := r.db.Exec(query, userID, tokenHash, userAgent, ip)
	return err
}

func (r *AuthPostgres) GetActiveRefreshToken(userID int) (model.RefreshToken, error) {
	var token model.RefreshToken
	query := `SELECT * FROM refresh_tokens WHERE user_id=$1 AND is_active=TRUE ORDER BY issued_at DESC LIMIT 1`
	err := r.db.Get(&token, query, userID)
	return token, err
}

func (r *AuthPostgres) DeactivateRefreshToken(tokenID int) error {
	query := `UPDATE refresh_tokens SET is_active=FALSE WHERE id=$1`
	_, err := r.db.Exec(query, tokenID)
	return err
}

func (r *AuthPostgres) GetRefreshTokenByHash(tokenHash string) (model.RefreshToken, error) {
	var token model.RefreshToken
	query := `SELECT * FROM refresh_tokens WHERE token_hash=$1 AND is_active=TRUE`
	err := r.db.Get(&token, query, tokenHash)
	return token, err
}

func (r *AuthPostgres) GetAllActiveRefreshTokens() ([]model.RefreshToken, error) {
	var tokens []model.RefreshToken
	query := `SELECT * FROM refresh_tokens WHERE is_active=TRUE`
	err := r.db.Select(&tokens, query)
	return tokens, err
}
