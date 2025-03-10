package main

import (
	"context"
	"log"
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
	cursor, err := TaskCollection.Find(context.Background(), bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	var tasks []Task
	if err = cursor.All(context.Background(), &tasks); err != nil {
		log.Fatal(err)
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
	var task Task
	if err := c.BindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	task.ID = primitive.NewObjectID()
	now := time.Now()
	task.CreatedAt = now
	task.UpdatedAt = now

	_, err := TaskCollection.InsertOne(context.Background(), task)
	if err != nil {
		log.Fatal(err)
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
	id := c.Param("id")
	objectID, _ := primitive.ObjectIDFromHex(id)

	var task Task
	if err := c.BindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	task.UpdatedAt = time.Now()

	update := bson.M{"$set": task}
	_, err := TaskCollection.UpdateOne(context.Background(), bson.M{"_id": objectID}, update)
	if err != nil {
		log.Fatal(err)
	}
	c.JSON(http.StatusOK, gin.H{"message": "Task updated"})
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
	id := c.Param("id")
	objectID, _ := primitive.ObjectIDFromHex(id)

	_, err := TaskCollection.DeleteOne(context.Background(), bson.M{"_id": objectID})
	if err != nil {
		log.Fatal(err)
	}
	c.JSON(http.StatusOK, gin.H{"message": "Task deleted"})
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
		err := UserCollection.FindOne(c, bson.M{"username": username}).Decode(&user)
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update role"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role updated successfully"})
}

func GetUserTasks(c *gin.Context) {
	username, _ := c.Get("username")
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

func CreateUserTask(c *gin.Context) {
	username, _ := c.Get("username")

	var task Task
	if err := c.BindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task.ID = primitive.NewObjectID()
	task.Assignee = username.(string) // Назначаем текущего пользователя исполнителем
	now := time.Now()
	task.CreatedAt = now
	task.UpdatedAt = now

	_, err := TaskCollection.InsertOne(context.Background(), task)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания задачи"})
		return
	}

	c.JSON(http.StatusCreated, task)
}

func UpdateUserTask(c *gin.Context) {
	username, _ := c.Get("username")
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

	res, err := TaskCollection.UpdateOne(context.Background(), filter, update)
	if err != nil || res.MatchedCount == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Вы не можете изменить эту задачу"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Задача обновлена"})
}
