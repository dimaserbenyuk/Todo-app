package main

import (
	"log"

	_ "github.com/dmytroserbeniuk/todo-backend/docs"
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
		AllowOrigins:     []string{"http://example.com", "http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length", "X-Custom-Header"},
		AllowCredentials: true,
	}))

	// Открытые маршруты (не требуют токена)
	r.POST("/api/v1/register", RegisterHandler)
	r.POST("/api/v1/login", LoginHandler)
	r.POST("/api/v1/logout", LogoutHandler)

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

		// Управление ролями (только Admin)
		auth.PUT("/user/role", RoleMiddleware(RoleAdmin), ChangeUserRole)

		// Обработка токенов
		auth.POST("/revoke", RevokeTokenHandler)
		auth.POST("/refresh", RefreshTokenHandler)
	}

	// Swagger документация
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Запуск сервера
	r.Run(":8080")
}
