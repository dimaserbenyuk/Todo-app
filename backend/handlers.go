package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// GetTasks - возвращает все задачи
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
func CreateTask(c *gin.Context) {
	var task Task
	if err := c.BindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	task.ID = primitive.NewObjectID()
	_, err := TaskCollection.InsertOne(context.Background(), task)
	if err != nil {
		log.Fatal(err)
	}
	c.JSON(http.StatusCreated, task)
}

// UpdateTask - обновляет задачу по ID
func UpdateTask(c *gin.Context) {
	id := c.Param("id")
	objectID, _ := primitive.ObjectIDFromHex(id)

	var task Task
	if err := c.BindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	update := bson.M{"$set": task}
	_, err := TaskCollection.UpdateOne(context.Background(), bson.M{"_id": objectID}, update)
	if err != nil {
		log.Fatal(err)
	}
	c.JSON(http.StatusOK, gin.H{"message": "Task updated"})
}

// DeleteTask - удаляет задачу по ID
func DeleteTask(c *gin.Context) {
	id := c.Param("id")
	objectID, _ := primitive.ObjectIDFromHex(id)

	_, err := TaskCollection.DeleteOne(context.Background(), bson.M{"_id": objectID})
	if err != nil {
		log.Fatal(err)
	}
	c.JSON(http.StatusOK, gin.H{"message": "Task deleted"})
}
