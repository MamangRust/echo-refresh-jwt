package service

import (
	"echoauthjwt/auth"
	"echoauthjwt/domain"
	"echoauthjwt/models"
	"echoauthjwt/repository"
	"errors"
	"fmt"
	"strconv"
)

type AuthService interface {
	Register(request domain.RegisterRequest) (*models.User, error)
	Login(email, password string) (*models.Token, error)
	RefreshToken(refreshToken string) (*models.Token, error)
	GetMe(token string) (*models.User, error)
}

type authService struct {
	token auth.TokenManager
	user  repository.UserRepository
}

func NewAuthService(user repository.UserRepository, token auth.TokenManager) *authService {
	return &authService{
		user:  user,
		token: token,
	}
}

func (s *authService) Register(request domain.RegisterRequest) (*models.User, error) {
	user := models.User{
		FirstName: request.FirstName,
		LastName:  request.LastName,
		Email:     request.Email,
		Password:  request.Password,
	}

	_, err := s.user.ReadByEmail(request.Email)

	if err == nil {
		return nil, errors.New("user already exist")
	}

	res, err := s.user.Create(user)

	if err != nil {
		return nil, errors.New("error creating user")
	}

	return res, nil
}

func (s *authService) Login(email, password string) (*models.Token, error) {
	res, err := s.user.ReadByEmail(email)

	if err != nil {
		return nil, err
	}

	if res.Password != password {
		return nil, err
	}

	token, err := s.createAccessToken(res.UserID)

	if err != nil {
		return nil, err
	}

	refreshToken, err := s.createRefreshToken(res.UserID)

	if err != nil {
		return nil, err
	}

	return &models.Token{
		AccessToken:  token,
		RefreshToken: refreshToken,
	}, nil
}

func (s *authService) RefreshToken(refreshToken string) (*models.Token, error) {
	res, err := s.token.ValidateToken(refreshToken)

	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	userId, err := strconv.Atoi(res)

	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	newToken, err := s.createAccessToken(userId)

	if err != nil {
		return nil, err
	}

	newRefreshToken, err := s.createRefreshToken(userId)

	if err != nil {
		return nil, err
	}

	return &models.Token{
		AccessToken:  newToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *authService) createAccessToken(id int) (string, error) {

	res, err := s.token.NewJwtToken(id, "access")
	if err != nil {
		return "", err
	}

	return res, nil
}

func (s *authService) createRefreshToken(id int) (string, error) {

	res, err := s.token.NewJwtToken(id, "refresh")

	if err != nil {
		return "", err
	}

	return res, nil
}

func (s *authService) GetMe(token string) (*models.User, error) {
	id, err := s.token.ValidateToken(token)

	if err != nil {
		return nil, errors.New("invalid token: " + err.Error())
	}

	fmt.Println("Id: ", id)

	idInt, err := strconv.Atoi(id)

	if err != nil {
		return nil, errors.New("invalid token")
	}

	res, err := s.user.Read(idInt)

	if err != nil {
		return nil, errors.New("user not found")
	}

	return res, nil
}
