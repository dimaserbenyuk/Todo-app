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
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Title       string             `bson:"title" json:"title"`
	Description string             `bson:"description,omitempty" json:"description,omitempty"`
	Completed   bool               `bson:"completed" json:"completed"`
	Priority    int                `bson:"priority,omitempty" json:"priority,omitempty"`
	DueDate     time.Time          `bson:"due_date,omitempty" json:"due_date,omitempty"`
	CreatedAt   time.Time          `bson:"created_at,omitempty" json:"created_at,omitempty"`
	UpdatedAt   time.Time          `bson:"updated_at,omitempty" json:"updated_at,omitempty"`
	Status      string             `bson:"status,omitempty" json:"status,omitempty"`
	Tags        []string           `bson:"tags,omitempty" json:"tags,omitempty"`

	// Поле для связи с пользователем
	Assignee string `bson:"assignee,omitempty" json:"assignee,omitempty"`
}

// User - структура пользователя в MongoDB
// @Description Структура для хранения данных о пользователе
// @Tags Users
// @Produce json
// User - структура пользователя в MongoDB
type User struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username  string             `bson:"username" json:"username"`
	Password  string             `bson:"password" json:"-"`
	CreatedAt time.Time          `bson:"created_at,omitempty" json:"created_at,omitempty"`
	Roles     []string           `bson:"roles" json:"roles"` // теперь массив ролей
}

// Token - структура для хранения JWT-токена
// @Description Структура, представляющая токен пользователя
// @Tags Auth
// @Produce json
type Token struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username  string             `bson:"username" json:"username"`
	Token     string             `bson:"token" json:"token"`
	ExpiresAt time.Time          `bson:"expires_at" json:"expires_at"`
	Revoked   bool               `bson:"revoked" json:"revoked"`
	TokenType string             `bson:"token_type" json:"token_type"` // "access" or "refresh"
}
