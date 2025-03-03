package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var (
	mongoClient *mongo.Client
)

func setupMongoDB() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	mongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal("Ошибка подключения к MongoDB:", err)
	}

	db := mongoClient.Database("testdb")
	UserCollection = db.Collection("users")
	TokenCollection = db.Collection("tokens")

	UserCollection.Drop(ctx)
	TokenCollection.Drop(ctx)
}

func teardownMongoDB() {
	if mongoClient != nil {
		mongoClient.Disconnect(context.Background())
	}
}

func TestMain(m *testing.M) {
	os.Setenv("JWT_SECRET", "testsecret")
	os.Setenv("JWT_ISSUER", "testissuer")
	os.Setenv("JWT_EXPIRATION_MINUTES", "10")

	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	jwtIssuer = os.Getenv("JWT_ISSUER")
	jwtExpirationMinutes, _ = strconv.Atoi(os.Getenv("JWT_EXPIRATION_MINUTES"))

	setupMongoDB()
	code := m.Run()
	teardownMongoDB()
	os.Exit(code)
}

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken("testuser")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestValidateToken(t *testing.T) {
	originalExpiration := jwtExpirationMinutes
	jwtExpirationMinutes = 10
	defer func() { jwtExpirationMinutes = originalExpiration }()

	token, err := GenerateToken("testuser")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := ValidateToken(token)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", claims.Username)
}

func TestRegisterHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/register", RegisterHandler)

	user := map[string]string{"username": "newuser", "password": "password123"}
	jsonData, _ := json.Marshal(user)

	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestLoginHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("/login", LoginHandler)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	_, err := UserCollection.InsertOne(context.TODO(), User{
		Username:  "existinguser",
		Password:  string(hashedPassword),
		CreatedAt: time.Now(),
	})
	assert.NoError(t, err)

	user := map[string]string{"username": "existinguser", "password": "password123"}
	jsonData, _ := json.Marshal(user)

	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.GET("/protected", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	token, _ := GenerateToken("testuser")
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
