package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// GetTasks - возвращает все задачи
// @Summary Получить список задач
// @Description Возвращает массив всех задач
// @Tags Tasks
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} Task "Список задач"
// @Failure 500 {object} gin.H "Ошибка сервера"
// @Router /tasks [get]
func GetTasks(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	cursor, err := TaskCollection.Find(context.TODO(), bson.M{"assignee": username})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения задач"})
		return
	}

	var tasks []Task
	if err = cursor.All(context.TODO(), &tasks); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки задач"})
		return
	}

	c.JSON(http.StatusOK, tasks)
}

// CreateTask - создает новую задачу
// @Summary Создать задачу
// @Description Добавляет новую задачу в базу данных
// @Tags Tasks
// @Accept json
// @Produce json
// @Param task body Task true "Данные новой задачи"
// @Success 201 {object} Task "Созданная задача"
// @Failure 400 {object} gin.H "Некорректные данные"
// @Failure 500 {object} gin.H "Ошибка сервера"
// @Security BearerAuth
// @Router /tasks [post]
func CreateTask(c *gin.Context) {
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
	task.CreatedAt = time.Now()
	task.UpdatedAt = time.Now()
	task.Assignee = username.(string) // Привязываем задачу к пользователю

	_, err := TaskCollection.InsertOne(context.TODO(), task)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания задачи"})
		return
	}

	c.JSON(http.StatusCreated, task)
}

// UpdateTask - обновляет задачу по ID
// @Summary Обновить задачу
// @Description Обновляет существующую задачу по её ID
// @Tags Tasks
// @Accept json
// @Produce json
// @Param id path string true "ID задачи"
// @Param task body Task true "Обновленные данные задачи"
// @Success 200 {object} gin.H "Сообщение об успешном обновлении"
// @Failure 400 {object} gin.H "Некорректные данные"
// @Failure 500 {object} gin.H "Ошибка сервера"
// @Security BearerAuth
// @Router /tasks/{id} [put]
func UpdateTask(c *gin.Context) {
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

// DeleteTask - удаляет задачу по ID
// @Summary Удалить задачу
// @Description Удаляет задачу по её ID
// @Tags Tasks
// @Accept json
// @Produce json
// @Param id path string true "ID задачи"
// @Success 200 {object} gin.H "Сообщение об успешном удалении"
// @Failure 500 {object} gin.H "Ошибка сервера"
// @Security BearerAuth
// @Router /tasks/{id} [delete]
func DeleteTask(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	id := c.Param("id")
	objectID, _ := primitive.ObjectIDFromHex(id)

	res, err := TaskCollection.DeleteOne(context.TODO(), bson.M{"_id": objectID, "assignee": username})
	if err != nil || res.DeletedCount == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Вы не можете удалить эту задачу"})
		return
	}

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

		for _, role := range allowedRoles {
			if user.Role == role {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
	}
}

func ChangeUserRole(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Role != RoleAdmin && req.Role != RoleManager && req.Role != RoleUser {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role"})
		return
	}

	_, err := UserCollection.UpdateOne(
		context.TODO(),
		bson.M{"username": req.Username},
		bson.M{"$set": bson.M{"role": req.Role}},
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось изменить роль"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Роль обновлена"})
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
