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
	jwt.RegisteredClaims
}

// GenerateToken - генерация JWT токена
func GenerateToken(username, role string) (string, error) {
	expirationTime := time.Now().Add(time.Duration(jwtExpirationMinutes) * time.Minute)
	claims := &Claims{
		Username: username,
		Role:     role,
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
	roles := []string{RoleUser}
	if count == 0 {
		roles = []string{RoleAdmin}
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
		Roles:     roles, // 👈 Записываем массив ролей
		CreatedAt: time.Now(),
	}

	// Сохраняем пользователя в базу
	_, err = UserCollection.InsertOne(context.TODO(), newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully", "roles": roles})
}

// LoginHandler - обработчик входа и генерации токенов
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

	// Поиск пользователя в MongoDB
	var user User
	err := UserCollection.FindOne(context.TODO(), bson.M{"username": req.Username}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Проверка пароля
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Берем первую роль пользователя (по умолчанию)
	userRole := RoleUser
	if len(user.Roles) > 0 {
		userRole = user.Roles[0] // 👈 Берем первую роль из списка
	}

	// Генерация Access Token
	accessToken, err := GenerateToken(user.Username, userRole)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate access token"})
		return
	}

	// Генерация Refresh Token
	refreshToken, refreshTokenExpiry, err := GenerateRefreshToken(user.Username, userRole)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate refresh token"})
		return
	}

	// ✅ Сохраняем токены в базе данных (MongoDB)
	tokenDocs := []interface{}{
		Token{
			ID:        primitive.NewObjectID(),
			Username:  user.Username,
			Token:     accessToken,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			Revoked:   false,
			TokenType: "access",
		},
		Token{
			ID:        primitive.NewObjectID(),
			Username:  user.Username,
			Token:     refreshToken,
			ExpiresAt: refreshTokenExpiry,
			Revoked:   false,
			TokenType: "refresh",
		},
	}

	_, err = TokenCollection.InsertMany(context.TODO(), tokenDocs)
	if err != nil {
		log.Println("❌ Ошибка сохранения токенов:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not store tokens"})
		return
	}

	// ✅ Устанавливаем токены в cookie
	c.SetCookie("token", accessToken, 60*60*24, "/", "localhost", false, true)
	c.SetCookie("refresh_token", refreshToken, 60*60*24*30, "/", "localhost", false, true)

	// ✅ Возвращаем успешный ответ
	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

// LogoutHandler удаляет Refresh Token из базы и cookie
func LogoutHandler(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh token found"})
		return
	}

	// ✅ 1️⃣ Удаляем `refresh_token` из базы
	if err := deleteRefreshTokenFromDB(refreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke refresh token"})
		return
	}

	// ✅ 2️⃣ Отзываем `access_token` (если он есть в заголовке)
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")
		err := RevokeToken(accessToken)
		if err != nil {
			log.Println("Ошибка отзыва access_token:", err)
		}
	}

	// ✅ 3️⃣ Очищаем куки у клиента
	c.SetCookie("token", "", -1, "/", "localhost", false, true)
	c.SetCookie("refresh_token", "", -1, "/", "localhost", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// AuthMiddleware - Middleware для проверки JWT-токена
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenString string

		// ✅ 1️⃣ Проверяем токен в заголовке Authorization
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			// ✅ 2️⃣ Если в заголовке нет токена, ищем его в куке
			cookieToken, err := c.Cookie("token")
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - token not found"})
				c.Abort()
				return
			}
			tokenString = cookieToken
		}

		// ✅ 3️⃣ Проверяем токен
		claims, err := ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// ✅ 4️⃣ Проверяем, не был ли токен отозван в MongoDB
		var storedToken Token
		err = TokenCollection.FindOne(context.TODO(), bson.M{"token": tokenString}).Decode(&storedToken)
		if err != nil || storedToken.Revoked {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token not found or revoked"})
			c.Abort()
			return
		}

		// ✅ 5️⃣ Сохраняем username в контексте Gin
		c.Set("username", claims.Username)

		c.Next()
	}
}

// func AuthMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		var tokenString string

// 		// 1. Проверяем токен в заголовке Authorization: Bearer <TOKEN>
// 		authHeader := c.GetHeader("Authorization")
// 		if strings.HasPrefix(authHeader, "Bearer ") {
// 			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
// 		}

// 		// 2. Если в заголовке нет, проверяем в cookie
// 		if tokenString == "" {
// 			cookieToken, err := c.Cookie("token")
// 			if err == nil {
// 				tokenString = cookieToken
// 			}
// 		}

// 		// 3. Если токена нет – ошибка
// 		if tokenString == "" {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - token not found"})
// 			c.Abort()
// 			return
// 		}

// 		// 4. Проверяем валидность токена
// 		claims, err := ValidateToken(tokenString)
// 		if err != nil {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 			c.Abort()
// 			return
// 		}

// 		// 5. Проверяем, есть ли токен в базе и не был ли он отозван
// 		var storedToken Token
// 		err = TokenCollection.FindOne(context.TODO(), bson.M{"token": tokenString}).Decode(&storedToken)
// 		if err != nil || storedToken.Revoked {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token not found or revoked"})
// 			c.Abort()
// 			return
// 		}

// 		// 6. Сохраняем данные пользователя в контексте Gin
// 		c.Set("username", claims.Username)
// 		c.Set("role", claims.Role)

// 		c.Next()
// 	}
// }

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

	// Проверяем refresh-токен в базе
	var storedToken Token
	err := TokenCollection.FindOne(context.TODO(), bson.M{
		"token":      req.RefreshToken,
		"revoked":    false,
		"token_type": "refresh",
	}).Decode(&storedToken)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or revoked refresh token"})
		return
	}

	// Валидируем refresh-токен как JWT
	claims, err := ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	username := claims.Username
	role := claims.Role

	// Генерируем новый access-токен
	newAccessToken, err := GenerateToken(username, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate access token"})
		return
	}

	// Генерируем новый refresh-токен
	newRefreshToken, refreshExpiry, err := GenerateRefreshToken(username, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate refresh token"})
		return
	}

	// Удаляем старый refresh-токен из базы
	_, err = TokenCollection.DeleteOne(context.TODO(), bson.M{"token": req.RefreshToken})
	if err != nil {
		log.Println("Ошибка удаления старого refresh-токена:", err)
	}

	// Сохраняем новые токены в базе
	tokenDocs := []interface{}{
		Token{
			ID:        primitive.NewObjectID(),
			Username:  username,
			Token:     newAccessToken,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			Revoked:   false,
			TokenType: "access",
		},
		Token{
			ID:        primitive.NewObjectID(),
			Username:  username,
			Token:     newRefreshToken,
			ExpiresAt: refreshExpiry,
			Revoked:   false,
			TokenType: "refresh",
		},
	}

	_, err = TokenCollection.InsertMany(context.TODO(), tokenDocs)
	if err != nil {
		log.Println("Ошибка сохранения новых токенов:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not store tokens"})
		return
	}

	// Устанавливаем новые токены в куки
	c.SetCookie("token", newAccessToken, 60*60*24, "/", "localhost", false, true)
	c.SetCookie("refresh_token", newRefreshToken, 60*60*24*30, "/", "localhost", false, true)

	// Возвращаем успешный ответ
	c.JSON(http.StatusOK, gin.H{"message": "Tokens refreshed successfully"})
}

func MeHandler(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"username": username})
}

// Хендлер (например, в handlers.go)
func GetUserTokenHandler(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var token Token
	err := TokenCollection.FindOne(
		context.TODO(),
		bson.M{
			"username":   username,
			"token_type": "api",
			"revoked":    false,
		},
	).Decode(&token)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No API token found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token.Token,
	})
}
