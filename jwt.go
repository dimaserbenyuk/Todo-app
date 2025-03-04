package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
var jwtIssuer = os.Getenv("JWT_ISSUER")
var jwtExpirationMinutes, _ = strconv.Atoi(os.Getenv("JWT_EXPIRATION_MINUTES"))

// Claims - структура для хранения данных в токене
type Claims struct {
	Username string `json:"username"`
	Device   string `json:"device,omitempty"`
	IP       string `json:"ip,omitempty"`
	jwt.RegisteredClaims
}

// GenerateToken - генерация JWT токена
func GenerateToken(username, device, ip string) (string, error) {
	expirationTime := time.Now().Add(time.Duration(jwtExpirationMinutes) * time.Minute)
	claims := &Claims{
		Username: username,
		Device:   device,
		IP:       ip,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    jwtIssuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ValidateToken - проверка JWT токена
func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		var storedToken Token
		err := TokenCollection.FindOne(context.TODO(), bson.M{"token": tokenString}).Decode(&storedToken)
		if err == nil && storedToken.Revoked {
			return nil, errors.New("token has been revoked")
		}
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

// RevokeToken - отзыв токена
func RevokeToken(tokenString string) error {
	_, err := TokenCollection.UpdateOne(
		context.TODO(),
		bson.M{"token": tokenString},
		bson.M{"$set": bson.M{"revoked": true}},
	)
	return err
}

// RegisterHandler - регистрация нового пользователя
func RegisterHandler(c *gin.Context) {
	type RegisterRequest struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var existingUser User
	err := UserCollection.FindOne(context.TODO(), bson.M{"username": req.Username}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	newUser := User{
		ID:        primitive.NewObjectID(),
		Username:  req.Username,
		Password:  string(hashedPassword),
		CreatedAt: time.Now(),
	}

	_, err = UserCollection.InsertOne(context.TODO(), newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}

// LoginHandler - обработчик входа и генерации токена
func LoginHandler(c *gin.Context) {
	type LoginRequest struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	err := UserCollection.FindOne(context.TODO(), bson.M{"username": req.Username}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	device := c.Request.Header.Get("User-Agent")
	ip := c.ClientIP()

	token, err := GenerateToken(user.Username, device, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate token"})
		return
	}

	_, err = TokenCollection.InsertOne(context.TODO(), Token{
		ID:        primitive.NewObjectID(),
		Username:  user.Username,
		Token:     token,
		Device:    device,
		IP:        ip,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Revoked:   false,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not store token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// LogoutHandler удаляет Refresh Token из базы и cookie
func LogoutHandler(c *gin.Context) {
	cookie, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh token found"})
		return
	}

	// Удаление Refresh Token из базы (реализуйте логику)
	if err := deleteRefreshTokenFromDB(cookie); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke session"})
		return
	}

	// Очистка cookie на клиенте
	c.SetCookie("refresh_token", "", -1, "/", "localhost", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// AuthMiddleware - Middleware для проверки JWT-токена
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		if tokenString == "" || !strings.HasPrefix(tokenString, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing token"})
			c.Abort()
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		claims, err := ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Сохранение данных токена в контексте запроса
		c.Set("username", claims.Username)
		c.Set("device", claims.Device)
		c.Set("ip", claims.IP)

		c.Next()
	}
}

// RevokeTokenHandler - обработчик отзыва токена
func RevokeTokenHandler(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" || !strings.HasPrefix(tokenString, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Токен отсутствует или некорректный"})
		return
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	// Проверяем, существует ли токен
	var existingToken Token
	err := TokenCollection.FindOne(context.TODO(), bson.M{"token": tokenString}).Decode(&existingToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Токен не найден"})
		return
	}

	if existingToken.Revoked {
		c.JSON(http.StatusConflict, gin.H{"error": "Токен уже отозван"})
		return
	}

	// Обновляем токен, помечая его как отозванный
	_, err = TokenCollection.UpdateOne(
		context.TODO(),
		bson.M{"token": tokenString},
		bson.M{"$set": bson.M{"revoked": true}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при отзыве токена"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Токен отозван"})
}

// deleteRefreshTokenFromDB - удаляет Refresh Token из базы данных
func deleteRefreshTokenFromDB(token string) error {
	// Предположим, что TokenCollection - это ваша коллекция в MongoDB для хранения токенов
	_, err := TokenCollection.DeleteOne(context.TODO(), bson.M{"token": token})
	return err
}
