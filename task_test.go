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
	return args.Get(0).(*Task), args.Error(1)
}

func (m *MockTaskService) GetTasks() ([]Task, error) {
	args := m.Called()
	return args.Get(0).([]Task), args.Error(1)
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
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		savedTask, err := mockService.CreateTask(task)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, savedTask)
	})

	newTask := Task{
		Title:       "Test task",
		Description: "Description of test task",
		Assignee:    "testuser",
	}

	mockService.On("CreateTask", mock.AnythingOfType("Task")).Return(&newTask, nil)

	jsonTask, _ := json.Marshal(newTask)
	req, _ := http.NewRequest(http.MethodPost, "/tasks", bytes.NewBuffer(jsonTask))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var responseTask Task
	_ = json.Unmarshal(w.Body.Bytes(), &responseTask)
	assert.Equal(t, newTask.Title, responseTask.Title)
	assert.Equal(t, newTask.Assignee, responseTask.Assignee)
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
		{Title: "Task 1", Completed: false},
		{Title: "Task 2", Completed: true},
	}

	mockService.On("GetTasks").Return(tasks, nil)

	req, _ := http.NewRequest(http.MethodGet, "/tasks", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateTaskHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockTaskService)
	router := gin.Default()

	router.PUT("/tasks/:id", func(c *gin.Context) {
		id := c.Param("id")
		var task Task
		if err := c.ShouldBindJSON(&task); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

	taskUpdate := Task{
		Title:     "Updated task title",
		Completed: true,
	}
	jsonTask, _ := json.Marshal(taskUpdate)

	mockService.On("UpdateTask", objectID, mock.Anything).Return(nil)

	req, _ := http.NewRequest(http.MethodPut, "/tasks/"+objectID, bytes.NewBuffer(jsonTask))
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
		if err := mockService.DeleteTask(id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete task"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Task deleted"})
	})

	taskID := primitive.NewObjectID().Hex()
	mockService.On("DeleteTask", taskID).Return(nil)

	req, _ := http.NewRequest(http.MethodDelete, "/tasks/"+taskID, nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
