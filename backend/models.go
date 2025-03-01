package main

import "go.mongodb.org/mongo-driver/bson/primitive"

// Task - структура для задачи
// @Description Структура для представления задачи
type Task struct {
	// @Description Уникальный идентификатор задачи
	// @example 60d5f8f6e4b0b3a520bdbb9b
	ID primitive.ObjectID `bson:"_id,omitempty" json:"id"`

	// @Description Название задачи
	// @example "Закупить продукты"
	Title string `bson:"title" json:"title"`

	// @Description Статус выполнения задачи
	// @example false
	Completed bool `bson:"completed" json:"completed"`
}