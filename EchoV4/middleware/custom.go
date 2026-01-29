package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// Cors Middleware
func Cors(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		//set cors headers
		c.Response().Header().Set("Access-control-allow-origin", "*")
		c.Response().Header().Set("Access control allow method", "GET,POST,PUT, DELETE, OPTIONS")
		c.Response().Header().Set("Access control allow headers", "Content-type, Authorization")

		//Handle preflight request
		if c.Request().Method == "OPTIONS" {
			return c.NoContent(http.StatusNoContent)
		}

		return next(c)
	}
}

// Authentication Middleware
func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		//Get token from header
		authHeader := c.Request().Header.Get("Authorization")

		if authHeader == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Authorization Header missing",
			})
		}

		//check if bearer token exists
		if !strings.HasPrefix(authHeader, "Bearer") {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid token format",
			})
		}

		token := strings.TrimPrefix(authHeader, "Bearer")

		//TODO: validate token (JWT,etc)...
		if token != "Secret-token" {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid token",
			})
		}

		//Set user info in context for later use
		c.Set("user_id", "123")
		c.Set("user_role", "admin")

		return next(c)
	}
}

// Logging middleware
func LoggingMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		//Before request
		c.Logger().Infof("Request %s %s ", c.Request().Method, c.Request().URL.Path)

		//Process Request
		err := next(c)

		//After Request
		if err != nil {
			c.Logger().Errorf("Error :%v", err)
		} else {
			c.Logger().Infof("Response:%d", c.Response().Status)
		}

		return err
	}
}
