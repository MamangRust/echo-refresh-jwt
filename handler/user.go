package handler

import (
	"echoauthjwt/auth"
	"echoauthjwt/service"
	"log"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

type UserHandler struct {
	auth  service.AuthService
	token auth.TokenManager
}

func NewUserHandler(auth service.AuthService, token auth.TokenManager) *UserHandler {
	return &UserHandler{
		auth:  auth,
		token: token,
	}
}

func (h *UserHandler) GetMe(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")

	tokenString := strings.Split(authHeader, " ")[1]

	user, err := h.auth.GetMe(tokenString)

	log.Println("USER", user)

	if err != nil {
		return c.JSON(http.StatusUnauthorized, err.Error())
	}

	return c.JSON(http.StatusOK, user)
}

func (h *UserHandler) Restricted(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")

	tokenString := strings.Split(authHeader, " ")[1]

	token, err := h.token.ValidateToken(tokenString)

	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, token)
}
