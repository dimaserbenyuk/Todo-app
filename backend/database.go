package main

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TaskCollection - коллекция задач в MongoDB
var TaskCollection *mongo.Collection

// UserCollection - коллекция пользователей в MongoDB
var UserCollection *mongo.Collection

// TokenCollection - коллекция токенов в MongoDB
var TokenCollection *mongo.Collection

// initDB - инициализация подключения к базе данных
func initDB() {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		log.Fatal("❌ MONGO_URI не задан в .env файле")
	}

	clientOptions := options.Client().ApplyURI(mongoURI).SetConnectTimeout(10 * time.Second)

	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatalf("❌ Ошибка подключения к MongoDB: %v", err)
	}

	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatalf("❌ Не удалось подключиться к MongoDB: %v", err)
	}

	// Устанавливаем коллекции
	TaskCollection = client.Database("todo_db").Collection("tasks")
	UserCollection = client.Database("todo_db").Collection("users")
	TokenCollection = client.Database("todo_db").Collection("tokens") // Добавлено

	log.Println("✅ Успешное подключение к MongoDB")
}
