package main

import (
	"echoauthjwt/auth"
	"echoauthjwt/dotenv"
	"echoauthjwt/handler"
	"echoauthjwt/repository"
	"echoauthjwt/service"
	"log"

	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var whiteListPaths = []string{
	"/login",
	"/register",
	"/refresh-token",
}

func WebSecurityConfig(e *echo.Echo) {
	config := echojwt.Config{
		SigningKey: []byte("secret"),
		Skipper:    skipAuth,
	}
	e.Use(echojwt.WithConfig(config))
}

func skipAuth(e echo.Context) bool {
	path := e.Path()
	for _, p := range whiteListPaths {
		if path == p {
			return true
		}
	}
	return false
}

func main() {
	e := echo.New()

	err := dotenv.LoadConfig()

	if err != nil {
		log.Fatal("Error: ", err)
	}

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	WebSecurityConfig(e)

	tokenManager, err := auth.NewManager("secret")
	if err != nil {
		e.Logger.Fatal(err)
	}

	userRepository := repository.NewUserRepository()

	authService := service.NewAuthService(userRepository, tokenManager)

	jwtHandler := handler.NewJWTHandler(authService)

	userHandler := handler.NewUserHandler(authService, tokenManager)

	// Login route
	e.POST("/login", jwtHandler.Login)
	e.POST("/register", jwtHandler.Register)
	e.POST("/refresh-token", jwtHandler.RefreshToken)

	r := e.Group("/restricted")

	r.GET("", userHandler.Restricted)
	r.GET("/me", userHandler.GetMe)

	e.Logger.Fatal(e.Start(":1323"))
}
