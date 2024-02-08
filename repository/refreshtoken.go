package repository

import (
	"echoauthjwt/models"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

type RefreshTokenRepository interface {
	CreateToken(userId int) (*models.RefreshToken, error)
	DeleteToken(token string) (bool, error)
}

type refreshTokenRepository struct {
	mu            sync.RWMutex
	refreshTokens map[string]models.RefreshToken
}

func NewRefreshTokenRepository() *refreshTokenRepository {
	return &refreshTokenRepository{
		refreshTokens: make(map[string]models.RefreshToken),
	}
}

func (r *refreshTokenRepository) CreateToken(userId int) (*models.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	token := uuid.New().String()
	expiration := time.Now().Add(time.Hour * 72)

	refreshToken := models.RefreshToken{
		UserID:     userId,
		Token:      token,
		Expiration: expiration,
	}

	r.refreshTokens[token] = refreshToken

	return &refreshToken, nil
}

func (r *refreshTokenRepository) DeleteToken(token string) (bool, error) {
	r.mu.Lock()

	defer r.mu.Lock()

	if _, ok := r.refreshTokens[token]; ok {
		delete(r.refreshTokens, token)
		return true, nil
	}

	return false, errors.New("refresh token not found")
}
