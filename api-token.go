package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// GenerateApiTokenHandler - генерирует дополнительный JWT (token_type = "api").
// Вызовем этот endpoint с фронтенда, и пользователь получит в ответ API-токен.
func GenerateApiTokenHandler(c *gin.Context) {
	// Проверяем авторизацию
	usernameVal, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	username := usernameVal.(string)

	// Можно взять роль из контекста, если нужно
	// roleVal, _ := c.Get("role")
	// role := roleVal.(string)

	// Или жестко задать role, или вытащить первую роль юзера из базы
	userRole := RoleUser // упрощенный вариант

	// Генерация нового JWT
	// (Та же GenerateToken, что и для access)
	apiToken, err := GenerateToken(username, userRole)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate API token"})
		return
	}

	// Сохраняем в MongoDB (token_type = "api")
	newToken := Token{
		ID:        primitive.NewObjectID(),
		Username:  username,
		Token:     apiToken,
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour), // Допустим, 1 год
		Revoked:   false,
		TokenType: "api",
	}

	_, err = TokenCollection.InsertOne(context.TODO(), newToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not store API token"})
		return
	}

	// Возвращаем токен клиенту
	c.JSON(http.StatusOK, gin.H{
		"api_token":  apiToken,
		"expires_at": newToken.ExpiresAt,
	})
}

// func GetUserTokenHandler(c *gin.Context) {
// 	username, exists := c.Get("username")
// 	if !exists {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
// 		return
// 	}

// 	var token Token
// 	err := TokenCollection.FindOne(
// 		context.TODO(),
// 		bson.M{
// 			"username":   username,
// 			"token_type": "api",
// 			"revoked":    false,
// 		},
// 	).Decode(&token)

// 	if err != nil {
// 		c.JSON(http.StatusNotFound, gin.H{"error": "No API token found"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{
// 		"token": token.Token,
// 	})
// }

// func GenerateUserTokenHandler(c *gin.Context) {
// 	username, exists := c.Get("username")
// 	if !exists {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
// 		return
// 	}

// 	// Генерируем токен (случайная строка)
// 	newApiToken := generateRandomToken(32) // например, hex/base64

// 	newToken := Token{
// 		ID:        primitive.NewObjectID(),
// 		Username:  username.(string),
// 		Token:     newApiToken,
// 		TokenType: "api",
// 		Revoked:   false,
// 		ExpiresAt: time.Now().Add(365 * 24 * time.Hour), // опционально
// 	}

// 	_, err := TokenCollection.InsertOne(context.TODO(), newToken)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not store token"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"token": newApiToken})
// }

// func generateRandomToken(n int) string {
// 	b := make([]byte, n)
// 	_, _ = rand.Read(b)
// 	return hex.EncodeToString(b)
// }

// func RevokeUserTokenHandler(c *gin.Context) {
// 	username, exists := c.Get("username")
// 	if !exists {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
// 		return
// 	}

// 	filter := bson.M{
// 		"username":   username,
// 		"token_type": "api",
// 		"revoked":    false,
// 	}

// 	update := bson.M{
// 		"$set": bson.M{
// 			"revoked": true,
// 		},
// 	}

// 	res, err := TokenCollection.UpdateOne(context.TODO(), filter, update)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not revoke token"})
// 		return
// 	}
// 	if res.MatchedCount == 0 {
// 		c.JSON(http.StatusNotFound, gin.H{"error": "No active API token found"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "Token revoked"})
// }
