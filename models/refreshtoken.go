package models

import "time"

type RefreshToken struct {
	UserID     int       `json:"user_id"`
	Token      string    `json:"token"`
	Expiration time.Time `json:"expiration"`
}
