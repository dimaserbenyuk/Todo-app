package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	TaskCollection  *mongo.Collection
	UserCollection  *mongo.Collection
	TokenCollection *mongo.Collection
	client          *mongo.Client
)

// initDB - инициализация подключения к базе данных
func initDB() {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		log.Fatal("❌ MONGO_URI не задан в .env файле")
	}

	// Определяем имя базы данных
	dbName := "todo_db"
	if os.Getenv("TEST_ENV") == "true" {
		dbName = "todo_test_db"
		log.Println("⚠️ Используется тестовая база данных")
	}

	// Получаем таймаут из env или используем 10 секунд по умолчанию
	timeout := 10 * time.Second
	if val := os.Getenv("MONGO_TIMEOUT"); val != "" {
		if parsedTimeout, err := time.ParseDuration(val); err == nil {
			timeout = parsedTimeout
		} else {
			log.Printf("⚠️ Некорректное значение MONGO_TIMEOUT (%s), используется 10s", val)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	clientOptions := options.Client().ApplyURI(mongoURI).SetConnectTimeout(timeout)

	var err error
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("❌ Ошибка подключения к MongoDB: %v", err)
	}

	// Пытаемся подключиться несколько раз перед фатальной ошибкой
	retries := 3
	for i := 0; i < retries; i++ {
		err = client.Ping(ctx, nil)
		if err == nil {
			break
		}
		log.Printf("⚠️ Не удалось подключиться к MongoDB (попытка %d/%d), ошибка: %v", i+1, retries, err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		log.Fatalf("❌ Не удалось подключиться к MongoDB после %d попыток: %v", retries, err)
	}

	// Устанавливаем коллекции
	TaskCollection = client.Database(dbName).Collection("tasks")
	UserCollection = client.Database(dbName).Collection("users")
	TokenCollection = client.Database(dbName).Collection("tokens")

	// Логируем URI без пароля для безопасности
	safeURI := maskMongoURI(mongoURI)
	log.Printf("✅ Успешное подключение к MongoDB: %s (База: %s)", safeURI, dbName)
}

// maskMongoURI - скрывает пароль в Mongo URI перед логированием
func maskMongoURI(uri string) string {
	if strings.Contains(uri, "@") {
		parts := strings.Split(uri, "@")
		return "mongodb://***:***@" + parts[1]
	}
	return uri
}

// CloseDB - закрывает соединение с базой данных
func CloseDB() {
	if client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Disconnect(ctx); err != nil {
			log.Printf("⚠️ Ошибка при закрытии подключения к MongoDB: %v", err)
		} else {
			log.Println("✅ Соединение с MongoDB закрыто")
		}
	}
}
