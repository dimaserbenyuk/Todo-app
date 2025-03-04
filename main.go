package main

import (
	"log"

	_ "github.com/dmytroserbeniuk/todo-backend/docs" // Подключение swagger документации
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title   API для управления задачами
// @version  1.0
// @description API для управления задачами

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Введите токен в формате "Bearer {token}"

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host   localhost:8080
// @BasePath  /api/v1/

// @schemes http
func main() {

	// Загружаем .env файл, если он существует
	err := godotenv.Load(".env")
	if err != nil {
		log.Println("No .env file found, proceeding without it")
	}

	// Инициализация базы данных
	initDB()

	// Создаём маршруты
	r := gin.Default()

	// Кастомная настройка CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://example.com", "http://localhost:3000"}, // Список разрешённых источников
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},                // Разрешённые HTTP методы
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},     // Разрешённые заголовки
		ExposeHeaders:    []string{"Content-Length", "X-Custom-Header"},           // Заголовки, которые будут доступны на клиенте
		AllowCredentials: true,                                                    // Разрешение на использование cookies или заголовков авторизации
	}))

	// Открытые маршруты (не требуют токена)
	r.POST("/api/v1/register", RegisterHandler) // ✅ Открытая регистрация
	r.POST("/api/v1/login", LoginHandler)       // ✅ Открытый вход

	// Защищённые маршруты (требуют токен)
	auth := r.Group("/api/v1")
	auth.Use(AuthMiddleware())
	{
		auth.GET("/tasks", GetTasks)
		auth.POST("/tasks", CreateTask)
		auth.PUT("/tasks/:id", UpdateTask)
		auth.DELETE("/tasks/:id", DeleteTask)
	}

	// Swagger документация
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Запуск сервера
	r.Run(":8080")
}
