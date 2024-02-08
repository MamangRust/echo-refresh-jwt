package middlewares

import (
	"echoauthjwt/auth"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

type JWTMiddleware struct {
	TokenManager auth.TokenManager
}

func NewJWTMiddleware(tokenManager auth.TokenManager) *JWTMiddleware {
	return &JWTMiddleware{
		TokenManager: tokenManager,
	}
}

func (mw *JWTMiddleware) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "missing authorization header")
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid authorization header format")
			}

			token := parts[1]

			userId, err := mw.TokenManager.ValidateToken(token) // Public key is not used in validation in this middleware
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired token")
			}

			c.Set("user_id", userId)

			return next(c)
		}
	}
}
