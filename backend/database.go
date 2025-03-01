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

// initDB - инициализация подключения к базе данных
func initDB() {
	// Загружаем MONGO_URI из переменных окружения
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		log.Fatal("❌ MONGO_URI не задан в .env файле")
	}

	// Настройки клиента MongoDB
	clientOptions := options.Client().ApplyURI(mongoURI).SetConnectTimeout(10 * time.Second)

	// Подключение к MongoDB
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatalf("❌ Ошибка подключения к MongoDB: %v", err)
	}

	// Проверка соединения
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatalf("❌ Не удалось подключиться к MongoDB: %v", err)
	}

	// Устанавливаем коллекцию
	TaskCollection = client.Database("todo_db").Collection("tasks")
	log.Println("✅ Успешное подключение к MongoDB")
}
