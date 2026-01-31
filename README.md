# Custom CORS Middleware for Echo

This package provides a simple CORS middleware for the Echo framework.

## Features
- Adds CORS headers to every response
- Handles preflight `OPTIONS` requests automatically
- Allows all origins (`*`), common HTTP methods, and headers

## Usage

Import the middleware and register it with your Echo instance:

```go
import (
    "github.com/labstack/echo/v4"
    "your-module/cors"
)

func main() {
    e := echo.New()

    // Register custom CORS middleware
    e.Use(cors.Middleware())

    // Example route
    e.GET("/hello", func(c echo.Context) error {
        return c.String(200, "Hello, World!")
    })

    e.Start(":8080")
}
