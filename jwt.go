package main

import (
	"context"
	"errors"
	"log"
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

var (
	jwtSecret            []byte
	jwtIssuer            string
	jwtExpirationMinutes int
	refreshTokenExpiry   int
)

func init() {
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	jwtIssuer = os.Getenv("JWT_ISSUER")
	var err error
	jwtExpirationMinutes, err = strconv.Atoi(os.Getenv("JWT_EXPIRATION_MINUTES"))
	if err != nil {
		log.Fatal("Invalid JWT_EXPIRATION_MINUTES value")
	}
	refreshTokenExpiry, err = strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRY_DAYS"))
	if err != nil {
		refreshTokenExpiry = 30 // По умолчанию 30 дней
	}

	if len(jwtSecret) == 0 {
		log.Fatal("JWT_SECRET is not set")
	}
}

// Claims - структура для хранения данных в токене
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Device   string `json:"device,omitempty"`
	IP       string `json:"ip,omitempty"`
	jwt.RegisteredClaims
}

// GenerateToken - генерация JWT токена
func GenerateToken(username, role, device, ip string) (string, error) {
	expirationTime := time.Now().Add(time.Duration(jwtExpirationMinutes) * time.Minute)
	claims := &Claims{
		Username: username,
		Role:     role,
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

	// Проверяем, существует ли хотя бы один пользователь в базе
	count, err := UserCollection.CountDocuments(context.TODO(), bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Если пользователей нет - назначаем первого админом
	role := RoleUser
	if count == 0 {
		role = RoleAdmin
		log.Println("Первый пользователь зарегистрирован как ADMIN")
	}

	// Проверяем, существует ли пользователь с таким именем
	var existingUser User
	err = UserCollection.FindOne(context.TODO(), bson.M{"username": req.Username}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}

	// Хэшируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	// Создаем нового пользователя
	newUser := User{
		ID:        primitive.NewObjectID(),
		Username:  req.Username,
		Password:  string(hashedPassword),
		Role:      role,
		CreatedAt: time.Now(),
	}

	// Сохраняем пользователя в базу
	_, err = UserCollection.InsertOne(context.TODO(), newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully", "role": role})
}

// LoginHandler - обработчик входа и генерации токена
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

	// Генерация Access Token
	accessToken, err := GenerateToken(user.Username, user.Role, device, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate access token"})
		return
	}

	// Генерация Refresh Token
	// Генерация Refresh Token с ролью
	refreshToken, refreshTokenExpiry, err := GenerateRefreshToken(user.Username, user.Role)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate refresh token"})
		return
	}

	// Сохраняем оба токена в базе данных
	_, err = TokenCollection.InsertOne(context.TODO(), Token{
		ID:        primitive.NewObjectID(),
		Username:  user.Username,
		Token:     accessToken,
		Device:    device,
		IP:        ip,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Revoked:   false,
		TokenType: "access",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not store access token"})
		return
	}

	_, err = TokenCollection.InsertOne(context.TODO(), Token{
		ID:        primitive.NewObjectID(),
		Username:  user.Username,
		Token:     refreshToken,
		Device:    device,
		IP:        ip,
		ExpiresAt: refreshTokenExpiry,
		Revoked:   false,
		TokenType: "refresh",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not store refresh token"})
		return
	}

	// Возвращаем оба токена
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
	log.Println("Сохраняем Refresh Token:", refreshToken)

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

		// Проверяем валидность JWT
		claims, err := ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Проверяем, есть ли токен в базе и не был ли он отозван
		var storedToken Token
		err = TokenCollection.FindOne(context.TODO(), bson.M{"token": tokenString}).Decode(&storedToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token not found"})
			c.Abort()
			return
		}

		if storedToken.Revoked {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has been revoked"})
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

// GenerateRefreshToken - генерация Refresh Token
func GenerateRefreshToken(username, role string) (string, time.Time, error) {
	expirationTime := time.Now().Add(time.Duration(refreshTokenExpiry) * 24 * time.Hour)
	claims := &Claims{
		Username: username,
		Role:     role, // <- обязательно передай роль сюда
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    jwtIssuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}
	return tokenString, expirationTime, nil
}

func ValidateRefreshToken(refreshToken string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("INVALID REFRESH TYPE")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("INVALID CLAIM TYPE")
	}

	return claims, nil
}

// RefreshTokenHandler - обработчик обновления токенов
func RefreshTokenHandler(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	log.Println("🔄 Запрос на обновление токена, получен refresh:", req.RefreshToken)

	// Проверяем токен в базе
	var storedToken Token
	err := TokenCollection.FindOne(context.TODO(), bson.M{"token": req.RefreshToken, "revoked": false}).Decode(&storedToken)
	if err != nil {
		log.Println("❌ Refresh токен не найден или отозван:", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or revoked token"})
		return
	}

	// Валидируем refresh токен
	claims, err := ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		log.Println("❌ Ошибка валидации Refresh Token:", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// Генерируем новый Access Token
	newAccessToken, err := GenerateToken(claims.Username, claims.Role, storedToken.Device, storedToken.IP)
	if err != nil {
		log.Println("❌ Ошибка генерации Access Token:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate access token"})
		return
	}

	// Если у refresh token осталось меньше 7 дней, выдаем новый
	timeRemaining := time.Until(storedToken.ExpiresAt)
	response := gin.H{"access_token": newAccessToken}

	if timeRemaining < (7 * 24 * time.Hour) {
		newRefreshToken, newExpiry, err := GenerateRefreshToken(claims.Username, claims.Role)
		if err != nil {
			log.Println("❌ Ошибка генерации нового Refresh Token:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
			return
		}

		log.Println("♻️ Обновление Refresh Token:", newRefreshToken)

		_, err = TokenCollection.UpdateOne(context.TODO(),
			bson.M{"token": req.RefreshToken},
			bson.M{"$set": bson.M{"token": newRefreshToken, "expires_at": newExpiry}},
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update refresh token"})
			return
		}

		response["refresh_token"] = newRefreshToken
	}

	c.JSON(http.StatusOK, response)
}
