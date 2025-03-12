package main

import (
	"context"
	"log"

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
	// Загружаем .env файл, если он существует
	err := godotenv.Load(".env")
	if err != nil {
		log.Println("⚠ No .env file found, proceeding without it")
	}

	// Инициализация базы данных
	initDB()

	// Настройка логгера с отправкой логов в Kafka
	kafkaLogger, err := logger.NewKafkaLogger([]string{"kafka:9092"}, "gin-logs")
	if err != nil {
		log.Fatalf("❌ Ошибка инициализации Kafka Logger: %v", err)
	}
	defer kafkaLogger.Close()

	log := logger.NewZapLogger(kafkaLogger)

	// Создание Consumer Group
	// Создание Consumer Group
	consumerGroup, err := kafka.NewConsumerGroup([]string{"kafka:9092"}, "tasks", "todo-consumer-group", log)
	if err != nil {
		log.Fatal("❌ Ошибка при создании Consumer Group", zap.Error(err))
	}
	defer consumerGroup.Close()

	// ✅ Запускаем Consumer Group в отдельной горутине
	ctx := context.Background()
	handler := &kafka.ConsumerHandler{Logger: log}
	go func() {
		consumerGroup.RegisterHandlerAndConsumeMessages(ctx, handler)
	}()

	// Создаём маршруты
	r := gin.New()
	r.Use(gin.Recovery())

	// Middleware для логирования запросов
	r.Use(func(c *gin.Context) {
		log.Info("Request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("client_ip", c.ClientIP()),
		)
		c.Next()
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
		// Admin и Manager имеют доступ ко всем задачам
		auth.GET("/tasks", RoleMiddleware(RoleAdmin, RoleManager), GetTasks)
		auth.POST("/tasks", RoleMiddleware(RoleAdmin, RoleManager), CreateTask)
		auth.PUT("/tasks/:id", RoleMiddleware(RoleAdmin, RoleManager), UpdateTask)

		// User работает только со своими задачами
		auth.GET("/user/tasks", RoleMiddleware(RoleUser), GetUserTasks)
		auth.POST("/user/tasks", RoleMiddleware(RoleUser), CreateUserTask)
		auth.PUT("/user/tasks/:id", RoleMiddleware(RoleUser), UpdateUserTask)

		// Удаление задач только для Admin
		auth.DELETE("/tasks/:id", RoleMiddleware(RoleAdmin), DeleteTask)

		// Управление пользователями (только Admin)
		auth.GET("/users", RoleMiddleware(RoleAdmin), GetUsers)
		auth.PUT("/users/role", RoleMiddleware(RoleAdmin), ChangeUserRole)
		auth.DELETE("/users/:id", RoleMiddleware(RoleAdmin), DeleteUser)

		// Обработка токенов
		auth.POST("/revoke", RevokeTokenHandler)
		auth.POST("/refresh", RefreshTokenHandler)
		auth.GET("/me", MeHandler)          // ✅ Проверка авторизации
		auth.POST("/logout", LogoutHandler) // ✅ Выход

		auth.GET("/profile", ProfileHandler)

		auth.POST("/token/generate_api", GenerateApiTokenHandler)
		auth.GET("/token", GetUserTokenHandler)
	}

	// Swagger документация
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Запуск сервера с обработкой ошибок
	if err := r.Run("0.0.0.0:8080"); err != nil {
		log.Fatal("❌ Ошибка запуска сервера:", zap.Error(err))
	}
}
