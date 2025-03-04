package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// MockTaskService - мок для TaskCollection
type MockTaskService struct {
	mock.Mock
}

func (m *MockTaskService) CreateTask(task Task) (*Task, error) {
	args := m.Called(task)
	result, _ := args.Get(0).(*Task)
	return result, args.Error(1)
}

func (m *MockTaskService) GetTasks() ([]Task, error) {
	args := m.Called()
	result, _ := args.Get(0).([]Task)
	return result, args.Error(1)
}

func (m *MockTaskService) UpdateTask(id string, task Task) error {
	args := m.Called(id, task)
	return args.Error(0)
}

func (m *MockTaskService) DeleteTask(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func TestCreateTaskHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockService := new(MockTaskService)
	router := gin.Default()

	router.POST("/tasks", func(c *gin.Context) {
		var task Task
		if err := c.ShouldBindJSON(&task); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		savedTask, err := mockService.CreateTask(task)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create task"})
			return
		}

		c.JSON(http.StatusCreated, savedTask)
	})

	task := Task{
		ID:        primitive.NewObjectID(),
		Title:     "Test Task",
		Completed: false,
	}

	mockService.On("CreateTask", mock.AnythingOfType("Task")).Return(&task, nil)

	body, _ := json.Marshal(task)
	req, _ := http.NewRequest(http.MethodPost, "/tasks", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var responseTask Task
	_ = json.Unmarshal(w.Body.Bytes(), &responseTask)
	assert.Equal(t, task.Title, responseTask.Title)
}

func TestGetTasksHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockTaskService)
	router := gin.Default()

	router.GET("/tasks", func(c *gin.Context) {
		tasks, err := mockService.GetTasks()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tasks"})
			return
		}
		c.JSON(http.StatusOK, tasks)
	})

	tasks := []Task{
		{ID: primitive.NewObjectID(), Title: "Task 1", Completed: false},
		{ID: primitive.NewObjectID(), Title: "Task 2", Completed: true},
	}

	mockService.On("GetTasks").Return(tasks, nil)

	req, _ := http.NewRequest(http.MethodGet, "/tasks", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var responseTasks []Task
	_ = json.Unmarshal(w.Body.Bytes(), &responseTasks)
	assert.Len(t, responseTasks, 2)
}

func TestUpdateTaskHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockTaskService)
	router := gin.Default()

	router.PUT("/tasks/:id", func(c *gin.Context) {
		id := c.Param("id")
		var task Task
		if err := c.ShouldBindJSON(&task); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		err := mockService.UpdateTask(id, task)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update task"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Task updated"})
	})

	objectID := primitive.NewObjectID().Hex()
	updatedTask := Task{Title: "Updated Task", Completed: true}

	mockService.On("UpdateTask", objectID, updatedTask).Return(nil)

	jsonData, _ := json.Marshal(updatedTask)
	req, _ := http.NewRequest(http.MethodPut, "/tasks/"+objectID, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteTaskHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockTaskService)
	router := gin.Default()

	router.DELETE("/tasks/:id", func(c *gin.Context) {
		id := c.Param("id")
		err := mockService.DeleteTask(id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete task"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Task deleted"})
	})

	objectID := primitive.NewObjectID().Hex()

	mockService.On("DeleteTask", objectID).Return(nil)

	req, _ := http.NewRequest(http.MethodDelete, "/tasks/"+objectID, nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// func TestCreateTaskHandler_InvalidData(t *testing.T) {
// 	gin.SetMode(gin.TestMode)

// 	mockService := &MockTaskService{}
// 	router := gin.Default()
// 	router.POST("/tasks", func(c *gin.Context) {
// 		var task Task
// 		if err := c.ShouldBindJSON(&task); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
// 			return
// 		}

// 		savedTask, err := mockService.CreateTask(task)
// 		if err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create task"})
// 			return
// 		}

// 		c.JSON(http.StatusCreated, savedTask)
// 	})

// 	// Ожидаем вызов метода CreateTask с любым аргументом и возвращаем ошибку
// 	mockService.On("CreateTask", mock.AnythingOfType("Task")).Return(nil, assert.AnError)

// 	req, _ := http.NewRequest(http.MethodPost, "/tasks", bytes.NewBuffer([]byte("{}")))
// 	req.Header.Set("Content-Type", "application/json")
// 	w := httptest.NewRecorder()

// 	router.ServeHTTP(w, req)

// 	assert.Equal(t, http.StatusBadRequest, w.Code)

// 	var resp map[string]string
// 	_ = json.Unmarshal(w.Body.Bytes(), &resp)
// 	assert.Equal(t, "Invalid request", resp["error"])
// }
