package model

type RefreshToken struct {
	ID        int    `db:"id"`
	UserID    int    `db:"user_id"`
	TokenHash string `db:"token_hash"`
	UserAgent string `db:"user_agent"`
	IP        string `db:"ip"`
	IsActive  bool   `db:"is_active"`
	IssuedAt  string `db:"issued_at"`
} 