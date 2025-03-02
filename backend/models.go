package main

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Task - структура для задачи
// @Description Структура для представления задачи
type Task struct {
	// @Description Уникальный идентификатор задачи
	// @example 60d5f8f6e4b0b3a520bdbb9b
	ID primitive.ObjectID `bson:"_id,omitempty" json:"id"`

	// @Description Название задачи
	// @example "Закупить продукты"
	Title string `bson:"title" json:"title"`

	// @Description Описание задачи
	// @example "Купить молоко, хлеб и фрукты"
	Description string `bson:"description,omitempty" json:"description,omitempty"`

	// @Description Статус выполнения задачи
	// @example false
	Completed bool `bson:"completed" json:"completed"`

	// @Description Приоритет задачи (1 - низкий, 2 - средний, 3 - высокий)
	// @example 2
	Priority int `bson:"priority,omitempty" json:"priority,omitempty"`

	// @Description Дата и время выполнения задачи (ISO 8601)
	// @example "2025-03-05T12:00:00Z"
	DueDate time.Time `bson:"due_date,omitempty" json:"due_date,omitempty"`

	// @Description Дата создания задачи
	// @example "2025-03-01T10:00:00Z"
	CreatedAt time.Time `bson:"created_at,omitempty" json:"created_at,omitempty"`

	// @Description Дата последнего обновления задачи
	// @example "2025-03-01T10:30:00Z"
	UpdatedAt time.Time `bson:"updated_at,omitempty" json:"updated_at,omitempty"`

	// @Description Статус задачи (pending, in_progress, done)
	// @example "in_progress"
	Status string `bson:"status,omitempty" json:"status,omitempty"`

	// @Description Теги задачи
	// @example ["work", "urgent"]
	Tags []string `bson:"tags,omitempty" json:"tags,omitempty"`

	// @Description Исполнитель задачи
	// @example "Иван Петров"
	Assignee string `bson:"assignee,omitempty" json:"assignee,omitempty"`
}

