// auth/auth.go
package auth

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenManager interface {
	NewJwtToken(userId int, audience string) (string, error)
	ValidateToken(accessToken string) (string, error)
}

type Manager struct {
	accessKey string
}

func NewManager(accessKey string) (*Manager, error) {
	if accessKey == "" {
		return nil, errors.New("empty secret key")
	}

	return &Manager{
		accessKey: accessKey,
	}, nil
}

func (m *Manager) NewJwtToken(userId int, audience string) (string, error) {
	nowTime := time.Now()
	expireTime := nowTime.Add(12 * time.Hour)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expireTime),
		Subject:   strconv.Itoa(userId),
		Audience:  []string{audience},
	})

	return token.SignedString([]byte(m.accessKey))
}

func (m *Manager) ValidateToken(accessToken string) (string, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (i interface{}, err error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(m.accessKey), nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("error get user claims from token")
	}

	return claims["sub"].(string), nil
}
