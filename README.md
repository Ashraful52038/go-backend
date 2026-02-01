Go Backend Project
Part-1:PostgreSQL and GORM
📋 Overview

A Go backend application demonstrating database operations with PostgreSQL using GORM ORM. Features include database connection management, CRUD operations, request/response handling, and structured API responses.

🚀 Quick Start
Prerequisites

    Go 1.19+

    PostgreSQL 12+

    Git

Installation
bash

# Clone the repository
git clone <repository-url>
cd go-backend

# Initialize Go module
go mod init github.com/ashraful/go-backend

# Install dependencies
go get gorm.io/gorm
go get gorm.io/driver/postgres

# Set up PostgreSQL database
sudo -u postgres psql -c "CREATE DATABASE sampledb;"

Configuration

Update database connection in main.go:
go

dsn := "host=localhost user=postgres dbname=sampledb port=5432 sslmode=disable timezone=Asia/Dhaka"

Run the Application
bash

go run main.go

📦 Core Components
1. Database Connection (main.go)
go

func connectDB() *gorm.DB {
    dsn := "host=localhost user=postgres dbname=sampledb port=5432 sslmode=disable timezone=Asia/Dhaka"
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    // ... error handling
    return db
}

2. Data Model (models/user.go)
go

type User struct {
    gorm.Model
    Name  string
    Email string
}

3. Request Structures

Product Request:
go

type ProductRequest struct {
    Name        string  `json:"name" validate:"required"`
    Price       float64 `json:"price" validate:"required,gt=0"`
    Stock       int     `json:"stock" validate:"gte=0"`
    Description string  `json:"description"`
}

User Request:
go

type UserRequest struct {
    Name  string `json:"name" validate:"required,min=2,max=100"`
    Email string `json:"email" validate:"required,email"`
}

4. API Response Format (response/api_response.go)
go

type APIResponse struct {
    Success bool        `json:"success"`
    Message string      `json:"message"`
    Data    interface{} `json:"data,omitempty"`
    Error   string      `json:"error,omitempty"`
}

🔧 API Endpoints (Conceptual)
User Management

    POST /api/users - Create new user

    GET /api/users - List all users

    GET /api/users/:id - Get user by ID

    PUT /api/users/:id - Update user

    DELETE /api/users/:id - Delete user

Product Management

    POST /api/products - Create product

    GET /api/products - List products with filters

    GET /api/products/search - Search products

    PUT /api/products/:id - Update product

    DELETE /api/products/:id - Delete product

📊 Database Operations
Migration
go

db.AutoMigrate(&models.User{})

Create
go

user := models.User{Name: "John", Email: "john@example.com"}
db.Create(&user)

Read
go

var users []models.User
db.Find(&users)

Update
go

db.Model(&user).Update("Email", "new@example.com")

Delete
go

db.Delete(&user)

🛠️ Development
Dependencies
bash

# Install all dependencies
go mod tidy

# Check for updates
go list -u -m all

Testing
bash

# Run tests
go test ./...

# Test with coverage
go test -cover ./...

Building
bash

# Build for current OS
go build -o backend-app main.go

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o backend-linux main.go

⚙️ Configuration
Environment Variables

Create .env file:
env

DB_HOST=localhost
DB_PORT=5432
DB_NAME=sampledb
DB_USER=postgres
DB_PASSWORD=your_password
DB_TIMEZONE=Asia/Dhaka

Database Configuration
go

func getDSN() string {
    host := os.Getenv("DB_HOST")
    user := os.Getenv("DB_USER")
    dbname := os.Getenv("DB_NAME")
    return fmt.Sprintf("host=%s user=%s dbname=%s port=%s sslmode=disable timezone=%s",
        host, user, dbname, port, timezone)
}

🔍 Code Examples
Complete CRUD Example
go

// Create
func createUser(db *gorm.DB, name, email string) error {
    user := models.User{Name: name, Email: email}
    result := db.Create(&user)
    return result.Error
}

// Read with conditions
func getUsersByEmail(db *gorm.DB, domain string) ([]models.User, error) {
    var users []models.User
    result := db.Where("email LIKE ?", "%@"+domain).Find(&users)
    return users, result.Error
}

Transaction Example
go

func createUserWithTransaction(db *gorm.DB, user models.User) error {
    return db.Transaction(func(tx *gorm.DB) error {
        if err := tx.Create(&user).Error; err != nil {
            return err
        }
        // Additional operations...
        return nil
    })
}

🐛 Common Issues & Solutions
1. Database Connection Failed

Issue: failed to connect database
Solution:

    Verify PostgreSQL is running: sudo systemctl status postgresql

    Check credentials in DSN

    Ensure database exists: psql -l

2. Migration Errors

Issue: Error creating table
Solution:

    Check model struct tags

    Verify database permissions

    Drop and recreate database if needed

3. Data Not Persisting

Issue: Data disappears after restart
Solution:

    Check for db.AutoMigrate() issues

    Verify transaction commits

    Check error handling after db.Create()

📈 Performance Tips

    Connection Pooling: Configure GORM connection pool

    Indexing: Add indexes for frequently queried columns

    Batch Operations: Use batch inserts for multiple records

    Selective Loading: Use Select() to load only needed fields

🤝 Contributing

    Fork the repository

    Create feature branch: git checkout -b feature-name

    Commit changes: git commit -m 'Add feature'

    Push to branch: git push origin feature-name

    Submit pull request

📄 License

This project is licensed under the MIT License.
🔗 Useful Links

    GORM Documentation

    PostgreSQL Go Driver

    Go Standard Library

    Project Repository

👥 Authors

    Ashraful - Initial work

🙏 Acknowledgments

    GORM team for the excellent ORM library

    PostgreSQL community

    Go developers community

Note: This is a demonstration project. For production use, add proper error handling, logging, security measures, and environment-based configuration.


Part-2: Echo v4 Go Backend Application
📋 Project Overview

A comprehensive Go backend application built with Echo v4 framework featuring RESTful API endpoints, middleware layers, request/response handling, and validation. This application demonstrates modern Go web development patterns with structured project organization.
📁 Project Structure
text

echo-v4-app/
├── main.go                    # Application entry point
├── handlers/                  # Request handlers
│   └── user.go               # User-related handlers
│   └── health.go             # Health check handler
├── middleware/               # Custom middleware
│   ├── builtin/             # Echo built-in middleware configurations
│   │   ├── setup.go         # Middleware setup
│   │   ├── cors.go          # CORS configuration
│   │   ├── security.go      # Security headers
│   │   ├── compression.go   # Gzip compression
│   │   └── logging.go       # Logging configuration
│   └── custom.go            # Custom middleware implementations
├── models/                   # Data models
│   ├── request/             # Request DTOs
│   │   ├── user.go          # User request structs
│   │   └── ...              # Other request models
│   └── response/            # Response DTOs
│       └── api_response.go  # Standard API response
└── README.md                # This file

🚀 Quick Start
Prerequisites

    Go 1.19+

    Echo v4 framework

    Git

Installation
bash

# Clone the repository
git clone <repository-url>
cd echo-v4-app

# Initialize Go module
go mod init echo-v4-app

# Install dependencies
go get github.com/labstack/echo/v4
go get github.com/go-playground/validator/v10
go get gorm.io/gorm
go get gorm.io/driver/postgres

# Run the application
go run main.go

Run Application
bash

go run main.go

Server starts at: http://localhost:8080
📦 Core Components
1. Main Application (main.go)
go

package main

import (
    "net/http"
    "echo-v4-app/handlers"
    builtin "echo-v4-app/middleware/builtin"
    "github.com/go-playground/validator/v10"
    "github.com/labstack/echo/v4"
)

type CustomValidator struct {
    validator *validator.Validate
}

func (cv *CustomValidator) Validate(i interface{}) error {
    if err := cv.validator.Struct(i); err != nil {
        return err
    }
    return nil
}

func main() {
    e := echo.New()
    e.Validator = &CustomValidator{validator: validator.New()}
    builtin.Setup(e)
    setupRoutes(e)
    
    // Start server
    if err := e.Start(":8080"); err != nil {
        e.Logger.Fatal(err)
    }
}

2. Handlers (handlers/)
Health Check Handler
go

func HealthCheck(c echo.Context) error {
    return c.JSON(http.StatusOK, map[string]interface{}{
        "status":  "healthy",
        "service": "go-backend",
        "version": "1.0.0",
    })
}

User CRUD Handlers
go

// Create user - POST /users
func CreateUser(c echo.Context) error {
    var req request.UserRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, response.ErrorResponse("Invalid request", err.Error()))
    }
    
    user := request.User{
        Id:    strconv.FormatInt(time.Now().Unix(), 10),
        Name:  req.Name,
        Email: req.Email,
        Age:   25,
    }
    
    return c.JSON(201, response.SuccessResponse("User created successfully", user))
}

// Get user - GET /users/:id
func GetUser(c echo.Context) error {
    id := c.Param("id")
    user := request.User{
        Id:    id,
        Name:  "Ashraful",
        Email: "xyz@mail.com",
        Age:   30,
    }
    return c.JSON(http.StatusOK, response.SuccessResponse("find user", user))
}

// Update user - PUT /users/:id
func UpdateUser(c echo.Context) error {
    id := c.Param("id")
    var req request.UpdateUserRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, response.ErrorResponse("Invalid request", err.Error()))
    }
    
    updatedUser := request.User{
        Id:    id,
        Name:  req.Name,
        Email: req.Email,
        Age:   25,
    }
    
    return c.JSON(http.StatusOK, response.SuccessResponse("User updated successfully", updatedUser))
}

// Delete user - DELETE /users/:id
func DeleteUser(c echo.Context) error {
    id := c.Param("id")
    return c.JSON(http.StatusOK, response.SuccessResponse("User Deleted Successfully", 
        map[string]string{"id": id}))
}

// Get all users - GET /users
func GetAllUsers(c echo.Context) error {
    users := []request.User{
        {Id: "1", Name: "Ashraful", Email: "ash@mail.com", Age: 25},
        {Id: "2", Name: "Rahim", Email: "rahim@mail.com", Age: 29},
    }
    return c.JSON(http.StatusOK, response.SuccessResponse("Users Retrieved Successfully", users))
}

3. Middleware Configurations (middleware/builtin/)
Setup Middleware (setup.go)
go

func Setup(e *echo.Echo) {
    // 1. Recovery - Recover from panics
    e.Use(middleware.Recover())
    
    // 2. CORS - Handle cross-origin requests
    e.Use(middleware.CORSWithConfig(CORSConfig()))
    
    // 3. Logging - Log all requests
    e.Use(middleware.LoggerWithConfig(LoggerConfig()))
    
    // 4. Body Limit - Prevent large payloads (10MB)
    e.Use(middleware.BodyLimit(BodyLimitConfig()))
    
    // 5. Decompress - Decompress incoming requests
    e.Use(middleware.DecompressWithConfig(DecompressConfig()))
    
    // 6. Compression - Gzip compress responses
    e.Use(middleware.GzipWithConfig(GzipConfig()))
    
    // 7. Security Headers
    e.Use(middleware.SecureWithConfig(SecurityConfig()))
    
    // 8. Request ID - Add unique ID to each request
    e.Use(middleware.RequestID())
}

CORS Configuration (cors.go)
go

func CORSConfig() middleware.CORSConfig {
    return middleware.CORSConfig{
        AllowOrigins: []string{
            "http://localhost:3000",
            "http://localhost:5173",
            "https://yourdomain.com",
        },
        AllowMethods: []string{
            echo.GET, echo.POST, echo.PUT, echo.DELETE,
            echo.PATCH, echo.OPTIONS, echo.HEAD,
        },
        AllowHeaders: []string{
            echo.HeaderOrigin, echo.HeaderContentType,
            echo.HeaderAccept, echo.HeaderAuthorization,
            "X-Requested-With", "X-CSRF-Token", "X-API-Key",
        },
        AllowCredentials: true,
        MaxAge: 86400, // 24 hours
    }
}

Security Configuration (security.go)
go

func SecurityConfig() middleware.SecureConfig {
    return middleware.SecureConfig{
        XSSProtection:      "1; mode=block",
        ContentTypeNosniff: "nosniff",
        XFrameOptions:      "DENY",
        HSTSMaxAge:         31536000,
        ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
    }
}

func BodyLimitConfig() string {
    return "10M" // 10MB limit
}

Logging Configuration (logging.go)
go

func LoggerConfig() middleware.LoggerConfig {
    return middleware.LoggerConfig{
        Format: `{"time":"${time_rfc3339_nano}","id":"${id}","remote_ip":"${remote_ip}",` +
            `"host":"${host}","method":"${method}","uri":"${uri}","user_agent":"${user_agent}",` +
            `"status":${status},"error":"${error}","latency":${latency},"latency_human":"${latency_human}"` +
            `,"bytes_in":${bytes_in},"bytes_out":${bytes_out}}` + "\n",
        CustomTimeFormat: "2006-01-02 15:04:05.00000",
    }
}

Compression Configuration (compression.go)
go

func GzipConfig() middleware.GzipConfig {
    return middleware.GzipConfig{
        Level: 5, // Compression level 1-9
    }
}

func DecompressConfig() middleware.DecompressConfig {
    return middleware.DecompressConfig{}
}

4. Custom Middleware (middleware/custom.go)
go

// CORS Middleware
func Cors(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        c.Response().Header().Set("Access-control-allow-origin", "*")
        c.Response().Header().Set("Access-control-allow-method", "GET,POST,PUT,DELETE,OPTIONS")
        c.Response().Header().Set("Access-control-allow-headers", "Content-type, Authorization")
        
        if c.Request().Method == "OPTIONS" {
            return c.NoContent(http.StatusNoContent)
        }
        return next(c)
    }
}

// Authentication Middleware
func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        authHeader := c.Request().Header.Get("Authorization")
        
        if authHeader == "" {
            return c.JSON(http.StatusUnauthorized, map[string]string{
                "error": "Authorization Header missing",
            })
        }
        
        if !strings.HasPrefix(authHeader, "Bearer ") {
            return c.JSON(http.StatusUnauthorized, map[string]string{
                "error": "Invalid token format",
            })
        }
        
        token := strings.TrimPrefix(authHeader, "Bearer ")
        
        // TODO: Validate JWT token
        if token != "Secret-token" {
            return c.JSON(http.StatusUnauthorized, map[string]string{
                "error": "Invalid token",
            })
        }
        
        // Set user info in context
        c.Set("user_id", "123")
        c.Set("user_role", "admin")
        
        return next(c)
    }
}

// Logging Middleware
func LoggingMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        c.Logger().Infof("Request %s %s", c.Request().Method, c.Request().URL.Path)
        
        err := next(c)
        
        if err != nil {
            c.Logger().Errorf("Error: %v", err)
        } else {
            c.Logger().Infof("Response: %d", c.Response().Status)
        }
        
        return err
    }
}

5. Request Models (models/request/)
go

// user.go
type User struct {
    Id    string `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
    Age   int    `json:"age"`
}

type UserRequest struct {
    Name  string `json:"name" validate:"required,min=2,max=100"`
    Email string `json:"email" validate:"required,email"`
}

type UpdateUserRequest struct {
    Name  string `json:"name" validate:"omitempty,min=2,max=100"`
    Email string `json:"email" validate:"omitempty,email"`
}

// product.go
type ProductRequest struct {
    Name        string  `json:"name" validate:"required"`
    Description string  `json:"description"`
    Price       float64 `json:"price" validate:"required,gt=0"`
    Stock       int     `json:"stock" validate:"gte=0"`
    Category    string  `json:"category"`
}

6. Response Models (models/response/)
go

type APIResponse struct {
    Success bool        `json:"success"`
    Message string      `json:"message"`
    Data    interface{} `json:"data,omitempty"`
    Error   string      `json:"error,omitempty"`
}

func SuccessResponse(message string, data interface{}) APIResponse {
    return APIResponse{
        Success: true,
        Message: message,
        Data:    data,
    }
}

func ErrorResponse(message string, err string) APIResponse {
    return APIResponse{
        Success: false,
        Message: message,
        Error:   err,
    }
}

🔧 API Endpoints
Health Check

    GET /health - Check application health status

User Management

    POST /users - Create new user

    GET /users/:id - Get user by ID

    PUT /users/:id - Update user

    DELETE /users/:id - Delete user

    GET /users - Get all users

API Versioning

    POST /api/v1/users - Versioned user creation

    PUT /api/v1/users/:id - Versioned user update (protected)

    DELETE /api/v1/users/:id - Versioned user delete (protected)

🛠️ Development Features
1. Validation

    Request validation using go-playground/validator

    Custom validator integration with Echo

    Validation tags in request structs

2. Middleware Pipeline
text

Request → Recovery → CORS → Logging → Body Limit → 
Decompress → Compression → Security → Request ID → Handler

3. Security Features

    CORS configuration

    Security headers (XSS, HSTS, CSP)

    Request size limiting

    Input validation

    Authentication middleware

4. Performance Features

    Gzip compression (level 5)

    Request/response compression

    Structured logging

    Request ID tracking

⚙️ Configuration
Development vs Production
go

// Development setup (less strict)
func SetupDevelopment(e *echo.Echo) {
    e.Use(middleware.Recover())
    e.Use(middleware.Logger())
    e.Use(middleware.CORS()) // Allow all origins in dev
}

// Production setup (strict)
func SetupProduction(e *echo.Echo) {
    Setup(e) // Use all configured middleware
}

Customizing Middleware
go

// Example: Custom CORS configuration
config := middleware.CORSConfig{
    AllowOrigins: []string{"https://production.com"},
    AllowMethods: []string{echo.GET, echo.POST},
    AllowHeaders: []string{echo.HeaderAuthorization},
    MaxAge:       3600,
}
e.Use(middleware.CORSWithConfig(config))

🧪 Testing the API
Using cURL
bash

# Health check
curl http://localhost:8080/health

# Create user
curl -X POST http://localhost:8080/users \
  -H "Content-Type: application/json" \
  -d '{"name":"John Doe","email":"john@example.com"}'

# Get all users
curl http://localhost:8080/users

# Get single user
curl http://localhost:8080/users/1

# Update user
curl -X PUT http://localhost:8080/users/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"John Updated","email":"john.updated@example.com"}'

# Delete user
curl -X DELETE http://localhost:8080/users/1

Using HTTP Client (Postman/Insomnia)

    Import the collection from docs/ directory

    Set base URL to http://localhost:8080

    Test all endpoints

🐛 Troubleshooting
Common Issues
1. Port Already in Use
bash

# Find process using port 8080
sudo lsof -i :8080

# Kill the process
sudo kill -9 <PID>

2. CORS Issues

    Ensure frontend origin is in AllowOrigins list

    Check if AllowCredentials matches frontend requirements

    Verify preflight requests are handled

3. Validation Errors
json

{
  "success": false,
  "message": "Invalid request",
  "error": "Field validation for 'Email' failed on the 'email' tag"
}

4. Large Request Body

    Default body limit is 10MB

    Adjust in security.go if needed

📈 Performance Tips

    Compression Level: Adjust Gzip level based on CPU/memory trade-off

    Logging Format: Use structured JSON logging for production

    Connection Pooling: Configure database connection pooling

    Caching: Implement response caching for frequently accessed data

    Rate Limiting: Add rate limiting middleware for public APIs

🔍 Monitoring
Log Output Format
json

{
  "time": "2024-01-01T12:00:00.000000Z",
  "id": "request-123",
  "remote_ip": "192.168.1.1",
  "host": "localhost:8080",
  "method": "POST",
  "uri": "/users",
  "user_agent": "curl/7.68.0",
  "status": 201,
  "error": "",
  "latency": 12345678,
  "latency_human": "12.345678ms",
  "bytes_in": 78,
  "bytes_out": 156
}

Health Check Response
json

{
  "status": "healthy",
  "service": "go-backend",
  "version": "1.0.0"
}

🤝 Contributing

    Fork the repository

    Create feature branch: git checkout -b feature-name

    Commit changes: git commit -m 'Add feature'

    Push to branch: git push origin feature-name

    Submit pull request

Development Guidelines

    Follow Go coding standards

    Add tests for new features

    Update documentation

    Maintain middleware order

📄 License

MIT License - see LICENSE file for details.
👥 Authors

    Ashraful - Initial work and architecture

🙏 Acknowledgments

    Echo framework team for excellent web framework

    Go community for best practices

    All contributors and users

🔗 Useful Links

    Echo Framework Documentation

    Go Validator

    GORM Documentation

    Project Repository

Note: This application demonstrates production-ready patterns. For actual production deployment, consider adding:

    Database integration

    Environment-based configuration

    Comprehensive testing

    Monitoring and alerting

    CI/CD pipeline

