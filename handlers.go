package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

// Глобальный логгер для zap
var zapLog *zap.Logger

// InitLogger инициализирует zap.Logger
func InitLogger(logger *zap.Logger) {
	zapLog = logger
}

// GetTasks - возвращает все задачи
func GetTasks(c *gin.Context) {
	role, _ := c.Get("role")

	var filter bson.M
	if role == RoleAdmin || role == RoleManager {
		filter = bson.M{}
	} else {
		username, exists := c.Get("username")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		filter = bson.M{"assignee": username}
	}

	cursor, err := TaskCollection.Find(context.TODO(), filter)
	if err != nil {
		zapLog.Error("Ошибка получения задач", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения задач"})
		return
	}
	defer cursor.Close(context.TODO())

	var tasks []Task
	if err = cursor.All(context.TODO(), &tasks); err != nil {
		zapLog.Error("Ошибка обработки задач", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки задач"})
		return
	}

	zapLog.Info("📋 Получены задачи", zap.Int("count", len(tasks)))
	c.JSON(http.StatusOK, tasks)
}

// CreateTask - создает новую задачу
func CreateTask(c *gin.Context) {
	// 🛠️ Обработчик паники (чтобы сервер не падал)
	defer func() {
		if r := recover(); r != nil {
			zapLog.Error("🔥 Panic caught in CreateTask", zap.Any("error", r))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		}
	}()

	// 🚨 Проверка zapLog
	if zapLog == nil {
		log.Println("❌ zapLog не инициализирован!")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера"})
		return
	}

	// 🚨 Проверка подключения к MongoDB
	if TaskCollection == nil {
		zapLog.Error("❌ MongoDB TaskCollection не инициализирована!")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера"})
		return
	}

	// 🚨 Проверка username
	username, exists := c.Get("username")
	if !exists {
		zapLog.Error("❌ Не удалось получить username из контекста")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	zapLog.Info("👤 Username получен", zap.String("username", username.(string)))

	// 🚨 Проверка данных запроса
	var task Task
	if err := c.BindJSON(&task); err != nil {
		zapLog.Warn("Ошибка валидации задачи", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 📌 Устанавливаем ID и временные метки
	task.ID = primitive.NewObjectID()
	task.CreatedAt = time.Now()
	task.UpdatedAt = time.Now()
	task.Assignee = username.(string)

	// 📌 Записываем в базу
	_, err := TaskCollection.InsertOne(context.TODO(), task)
	if err != nil {
		zapLog.Error("Ошибка создания задачи", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания задачи"})
		return
	}

	zapLog.Info("✅ Создана новая задача", zap.String("title", task.Title), zap.String("assignee", task.Assignee))
	c.JSON(http.StatusCreated, task)
}

// UpdateTask - обновляет задачу по ID
func UpdateTask(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	id := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		zapLog.Warn("Некорректный ID задачи", zap.String("id", id))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный ID"})
		return
	}

	var task Task
	if err := c.BindJSON(&task); err != nil {
		zapLog.Warn("Ошибка валидации обновления задачи", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректные данные"})
		return
	}

	task.UpdatedAt = time.Now()

	filter := bson.M{"_id": objectID, "assignee": username}
	update := bson.M{"$set": task}

	res, err := TaskCollection.UpdateOne(context.TODO(), filter, update)
	if err != nil || res.MatchedCount == 0 {
		zapLog.Warn("Ошибка обновления задачи", zap.String("id", id))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Вы не можете изменить эту задачу"})
		return
	}

	zapLog.Info("✅ Задача обновлена", zap.String("id", id))
	c.JSON(http.StatusOK, gin.H{"message": "Задача обновлена"})
}

// DeleteTask - удаляет задачу по ID
func DeleteTask(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	id := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		zapLog.Warn("Некорректный ID задачи", zap.String("id", id))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный ID"})
		return
	}

	res, err := TaskCollection.DeleteOne(context.TODO(), bson.M{"_id": objectID, "assignee": username})
	if err != nil || res.DeletedCount == 0 {
		zapLog.Warn("Ошибка удаления задачи", zap.String("id", id))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Вы не можете удалить эту задачу"})
		return
	}

	zapLog.Info("🗑️ Задача удалена", zap.String("id", id))
	c.JSON(http.StatusOK, gin.H{"message": "Задача удалена"})
}

// RoleMiddleware проверяет, есть ли у пользователя нужная роль
func RoleMiddleware(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, exists := c.Get("username")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		var user User
		err := UserCollection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		// Проверяем, есть ли хотя бы одна роль из списка
		for _, role := range allowedRoles {
			for _, userRole := range user.Roles {
				if role == userRole {
					c.Next()
					return
				}
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
	}
}

func ChangeUserRole(c *gin.Context) {
	var req struct {
		Username string   `json:"username" binding:"required"`
		Roles    []string `json:"roles" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Проверяем, есть ли такой пользователь
	var user User
	err := UserCollection.FindOne(context.TODO(), bson.M{"username": req.Username}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Обновляем роли в MongoDB
	_, err = UserCollection.UpdateOne(
		context.TODO(),
		bson.M{"username": req.Username},
		bson.M{"$set": bson.M{"roles": req.Roles}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update roles"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Roles updated successfully"})
}

// GetUserTasks - получает задачи, принадлежащие текущему пользователю
func GetUserTasks(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	cursor, err := TaskCollection.Find(context.TODO(), bson.M{"assignee": username})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера"})
		return
	}

	var tasks []Task
	if err = cursor.All(context.TODO(), &tasks); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения задач"})
		return
	}

	c.JSON(http.StatusOK, tasks)
}

// CreateUserTask - создаёт задачу для текущего пользователя
func CreateUserTask(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var task Task
	if err := c.BindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task.ID = primitive.NewObjectID()
	task.Assignee = username.(string) // Назначаем текущего пользователя исполнителем
	task.CreatedAt = time.Now()
	task.UpdatedAt = time.Now()

	_, err := TaskCollection.InsertOne(context.TODO(), task)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания задачи"})
		return
	}

	c.JSON(http.StatusCreated, task)
}

// UpdateUserTask - обновляет задачу пользователя
func UpdateUserTask(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	id := c.Param("id")
	objectID, _ := primitive.ObjectIDFromHex(id)

	var task Task
	if err := c.BindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректные данные"})
		return
	}
	task.UpdatedAt = time.Now()

	filter := bson.M{"_id": objectID, "assignee": username}
	update := bson.M{"$set": task}

	res, err := TaskCollection.UpdateOne(context.TODO(), filter, update)
	if err != nil || res.MatchedCount == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Вы не можете изменить эту задачу"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Задача обновлена"})
}

func DeleteUser(c *gin.Context) {
	id := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	_, err = UserCollection.DeleteOne(context.Background(), bson.M{"_id": objectID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func GetUsers(c *gin.Context) {
	cursor, err := UserCollection.Find(context.Background(), bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	var users []User
	if err = cursor.All(context.Background(), &users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse users"})
		return
	}

	c.JSON(http.StatusOK, users)
}
