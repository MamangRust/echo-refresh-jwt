// handler/handler.go
package handler

import (
	"echoauthjwt/domain"
	"echoauthjwt/service"
	"net/http"

	"github.com/labstack/echo/v4"
)

type JWTHandler struct {
	auth service.AuthService
}

func NewJWTHandler(auth service.AuthService) *JWTHandler {
	return &JWTHandler{
		auth: auth,
	}
}

func (h *JWTHandler) Register(c echo.Context) error {
	var request domain.RegisterRequest
	if err := c.Bind(&request); err != nil {
		return err
	}

	user, err := h.auth.Register(request)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, user)
}

func (h *JWTHandler) Login(c echo.Context) error {
	var request domain.LoginRequest
	if err := c.Bind(&request); err != nil {
		return err
	}

	token, err := h.auth.Login(request.Email, request.Password)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, token)
}

func (h *JWTHandler) RefreshToken(c echo.Context) error {
	refreshToken := c.FormValue("refresh_token")

	token, err := h.auth.RefreshToken(refreshToken)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, token)
}
