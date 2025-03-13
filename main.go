package main

import (
	"context"
	"log"
	"time"

	_ "github.com/dmytroserbeniuk/todo-backend/docs"
	"github.com/dmytroserbeniuk/todo-backend/kafka"
	"github.com/dmytroserbeniuk/todo-backend/logger"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.uber.org/zap"
)

// @title API для управления задачами
// @version 1.0
// @description API для управления задачами

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Введите токен в формате "Bearer {token}"

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:8080
// @BasePath /api/v1/

// @schemes http
func main() {
	// ✅ Глобальная переменная для логгера
	var zapLog *zap.Logger

	// Загружаем .env файл
	err := godotenv.Load(".env")
	if err != nil {
		log.Println("⚠ No .env file found, proceeding without it")
	}

	// Инициализация базы данных
	initDB()

	// ✅ Настройка логгера с Kafka
	kafkaLogger, err := logger.NewKafkaLogger([]string{"kafka:9092"}, "gin-logs")
	if err != nil {
		log.Fatalf("❌ Ошибка инициализации Kafka Logger: %v", err)
	}
	defer kafkaLogger.Close()

	// ✅ Инициализация zap логгера
	zapLog = logger.NewZapLogger(kafkaLogger)

	// ✅ Передаем zapLog в handlers.go
	InitLogger(zapLog)

	// ✅ Создание Consumer Group
	consumerGroup, err := kafka.NewConsumerGroup([]string{"kafka:9092"}, "tasks", "todo-consumer-group", zapLog)
	if err != nil {
		zapLog.Fatal("❌ Ошибка при создании Consumer Group", zap.Error(err))
	}
	defer consumerGroup.Close()

	// ✅ Запускаем Consumer Group в отдельной горутине
	ctx := context.Background()
	handler := &kafka.ConsumerHandler{Logger: zapLog}
	go func() {
		zapLog.Info("🚀 Запуск Kafka Consumer Group")
		consumerGroup.RegisterHandlerAndConsumeMessages(ctx, handler)
	}()

	// ✅ Запуск сервера
	r := gin.New()
	r.Use(gin.Recovery())

	// ✅ Middleware для обработки паники (чтобы сервер не падал)
	r.Use(func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				zapLog.Error("🔥 Panic caught",
					zap.Any("error", err),
					zap.String("path", c.Request.URL.Path),
					zap.String("method", c.Request.Method),
					zap.String("client_ip", c.ClientIP()),
				)
				c.JSON(500, gin.H{"error": "Internal Server Error"})
				c.Abort()
			}
		}()
		c.Next()
	})

	// ✅ Middleware для детального логирования всех запросов
	r.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)

		LogRequest(zapLog,
			c.Request.Method,
			c.Request.URL.Path,
			c.ClientIP(),
			c.Request.UserAgent(),
			c.Writer.Status(),
			latency,
		)
	})

	// Кастомная настройка CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length", "X-Custom-Header"},
		AllowCredentials: true,
	}))

	// Открытые маршруты (не требуют токена)
	r.POST("/api/v1/register", RegisterHandler)
	r.POST("/api/v1/login", LoginHandler)

	// Защищённые маршруты (требуют токен)
	auth := r.Group("/api/v1")
	auth.Use(AuthMiddleware())
	{
		auth.GET("/tasks", RoleMiddleware(RoleAdmin, RoleManager), GetTasks)
		auth.POST("/tasks", RoleMiddleware(RoleAdmin, RoleManager), CreateTask)
		auth.PUT("/tasks/:id", RoleMiddleware(RoleAdmin, RoleManager), UpdateTask)

		auth.GET("/user/tasks", RoleMiddleware(RoleUser), GetUserTasks)
		auth.POST("/user/tasks", RoleMiddleware(RoleUser), CreateUserTask)
		auth.PUT("/user/tasks/:id", RoleMiddleware(RoleUser), UpdateUserTask)

		auth.DELETE("/tasks/:id", RoleMiddleware(RoleAdmin), DeleteTask)
		auth.GET("/users", RoleMiddleware(RoleAdmin), GetUsers)
		auth.PUT("/users/role", RoleMiddleware(RoleAdmin), ChangeUserRole)
		auth.DELETE("/users/:id", RoleMiddleware(RoleAdmin), DeleteUser)

		auth.POST("/revoke", RevokeTokenHandler)
		auth.POST("/refresh", RefreshTokenHandler)
		auth.GET("/me", MeHandler)
		auth.POST("/logout", LogoutHandler)

		auth.GET("/profile", ProfileHandler)
		auth.POST("/token/generate_api", GenerateApiTokenHandler)
		auth.GET("/token", GetUserTokenHandler)
	}

	// ✅ Swagger документация
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// ✅ Запуск сервера с логированием ошибок
	if err := r.Run("0.0.0.0:8080"); err != nil {
		zapLog.Fatal("❌ Ошибка запуска сервера:", zap.Error(err))
	}
}

// ✅ Функция логирования запросов
func LogRequest(log *zap.Logger, method, path, ip, userAgent string, status int, latency time.Duration) {
	log.Info("🌍 HTTP-запрос",
		zap.String("method", method),
		zap.String("path", path),
		zap.String("client_ip", ip),
		zap.String("user_agent", userAgent),
		zap.Int("status", status),
		zap.Duration("latency", latency),
	)
}
