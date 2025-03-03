package main

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Task - структура для задачи
// @Description Структура, представляющая задачу в системе
// @Tags Tasks
// @Produce json
type Task struct {
	// ID - Уникальный идентификатор задачи
	// @example 60d5f8f6e4b0b3a520bdbb9b
	ID primitive.ObjectID `bson:"_id,omitempty" json:"id"`

	// Title - Название задачи
	// @example "Закупить продукты"
	Title string `bson:"title" json:"title"`

	// Description - Описание задачи
	// @example "Купить молоко, хлеб и фрукты"
	Description string `bson:"description,omitempty" json:"description,omitempty"`

	// Completed - Статус выполнения задачи
	// @example false
	Completed bool `bson:"completed" json:"completed"`

	// Priority - Приоритет задачи (1 - низкий, 2 - средний, 3 - высокий)
	// @example 2
	Priority int `bson:"priority,omitempty" json:"priority,omitempty"`

	// DueDate - Дата и время выполнения задачи (ISO 8601)
	// @example "2025-03-05T12:00:00Z"
	DueDate time.Time `bson:"due_date,omitempty" json:"due_date,omitempty"`

	// CreatedAt - Дата создания задачи
	// @example "2025-03-01T10:00:00Z"
	CreatedAt time.Time `bson:"created_at,omitempty" json:"created_at,omitempty"`

	// UpdatedAt - Дата последнего обновления задачи
	// @example "2025-03-01T10:30:00Z"
	UpdatedAt time.Time `bson:"updated_at,omitempty" json:"updated_at,omitempty"`

	// Status - Статус задачи (pending, in_progress, done)
	// @example "in_progress"
	Status string `bson:"status,omitempty" json:"status,omitempty"`

	// Tags - Теги задачи
	// @example ["work", "urgent"]
	Tags []string `bson:"tags,omitempty" json:"tags,omitempty"`

	// Assignee - Исполнитель задачи
	// @example "Иван Петров"
	Assignee string `bson:"assignee,omitempty" json:"assignee,omitempty"`
}

// User - структура пользователя в MongoDB
// @Description Структура для хранения данных о пользователе
// @Tags Users
// @Produce json
type User struct {
	// ID - Уникальный идентификатор пользователя
	// @example 60d5f8f6e4b0b3a520bdbb9c
	ID primitive.ObjectID `bson:"_id,omitempty" json:"id"`

	// Username - Имя пользователя
	// @example "ivan_petrov"
	Username string `bson:"username" json:"username"`

	// Password - Хэш пароля пользователя
	// @example "hashed_password"
	Password string `bson:"password" json:"-"`

	// CreatedAt - Дата регистрации пользователя
	// @example "2025-03-01T10:00:00Z"
	CreatedAt time.Time `bson:"created_at,omitempty" json:"created_at,omitempty"`
}

// Token - структура для хранения JWT-токена
// @Description Структура, представляющая токен пользователя
// @Tags Auth
// @Produce json
type Token struct {
	// ID - Уникальный идентификатор токена
	// @example 60d5f8f6e4b0b3a520bdbb9d
	ID primitive.ObjectID `bson:"_id,omitempty" json:"id"`

	// Username - Имя пользователя, связанного с токеном
	// @example "ivan_petrov"
	Username string `bson:"username" json:"username"`

	// Token - Сам JWT-токен
	// @example "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
	Token string `bson:"token" json:"token"`

	// ExpiresAt - Дата истечения срока действия токена
	// @example "2025-03-02T10:00:00Z"
	ExpiresAt time.Time `bson:"expires_at" json:"expires_at"`
}
