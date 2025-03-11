package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

// ProfileHandler - возвращает информацию о пользователе
func ProfileHandler(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Ищем пользователя в базе
	var user User
	err := UserCollection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Подсчитываем количество созданных задач
	taskCount, err := TaskCollection.CountDocuments(context.TODO(), bson.M{"assignee": username})
	if err != nil {
		taskCount = 0
	}

	// Генерация Gravatar URL через SHA-256
	avatarURL := getGravatarURLSHA256(user.Email, 100)

	// Формируем ответ
	profile := gin.H{
		"username":   user.Username,
		"email":      user.Email,
		"roles":      user.Roles,
		"created_at": user.CreatedAt,
		"task_count": taskCount,
		"avatar_url": avatarURL,
	}

	c.JSON(http.StatusOK, profile)
}

// getGravatarURLSHA256 генерирует SHA-256 хеш e-mail,
// затем возвращает URL для Gravatar
func getGravatarURLSHA256(email string, size int) string {
	if email == "" {
		// Если email пустой, возвращаем Gravatar с дефолтной заглушкой
		return fmt.Sprintf("https://www.gravatar.com/avatar/?d=mp&s=%d", size)
	}
	trimmed := strings.TrimSpace(strings.ToLower(email))
	hashBytes := sha256.Sum256([]byte(trimmed))
	hash := hex.EncodeToString(hashBytes[:])
	return fmt.Sprintf("https://www.gravatar.com/avatar/%s?d=mp&s=%d", hash, size)
}
