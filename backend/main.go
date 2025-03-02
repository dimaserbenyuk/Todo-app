package main

import (
	"log"

	_ "github.com/dmytroserbeniuk/todo-backend/docs" // Подключение swagger документации
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv" // Импортируем godotenv
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title   API для управления задачами
// @version  1.0
// @description API для управления задачами

// @securityDefinitions.apiKey JWT
// @in       header
// @name      token

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host   localhost:8080
// @BasePath  /api/v1/

// @schemes http
func main() {
	// Загружаем .env файл
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Инициализация базы данных
	initDB()

	// Создаём маршруты
	r := gin.Default()

	v1 := r.Group("/api/v1")
	{
		// Маршрут для входа и получения JWT
		v1.POST("/login", LoginHandler)

		// @Summary Получить все задачи
		// @Tags tasks
		// @Success 200 {array} Task
		// @Router /tasks [get]
		v1.GET("/tasks", GetTasks)

		v1.Use(AuthMiddleware())

		// @Summary Создать новую задачу
		// @Tags tasks
		// @Param task body Task true "Task to create"
		// @Success 201 {object} Task
		// @Router /tasks [post]
		v1.POST("/tasks", CreateTask)

		// @Summary Обновить задачу
		// @Tags tasks
		// @Param id path string true "Task ID"
		// @Param task body Task true "Updated task"
		// @Success 200 {object} Task
		// @Failure 400 {object} gin.H{"error": "Bad request"}
		// @Router /tasks/{id} [put]
		v1.PUT("/tasks/:id", UpdateTask)

		// @Summary Удалить задачу
		// @Tags tasks
		// @Param id path string true "Task ID"
		// @Success 204 {object} nil
		// @Failure 404 {object} gin.H{"error": "Task not found"}
		// @Router /tasks/{id} [delete]
		v1.DELETE("/tasks/:id", DeleteTask)
	}

	// Swagger документация
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Запуск сервера
	r.Run(":8080")
}
