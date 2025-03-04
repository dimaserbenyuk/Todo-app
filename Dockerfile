# Этап 1: Сборка
FROM golang:1.23.6-alpine AS builder

# Установим рабочую директорию
WORKDIR /app

# Копируем только файлы зависимостей и выполняем их загрузку
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходный код
COPY . .

# Устанавливаем swag
RUN go install github.com/swaggo/swag/cmd/swag@latest

# Генерируем Swagger документацию
RUN swag init --parseDependency --parseInternal

# Сборка приложения
RUN go build -o todo-app

# Этап 2: Запуск
FROM alpine:latest

# Устанавливаем необходимые зависимости для работы с Go-программами (если нужно)
RUN apk add --no-cache libc6-compat ca-certificates

# Устанавливаем рабочую директорию
WORKDIR /root/

# Копируем собранное приложение из предыдущего этапа
COPY --from=builder /app/todo-app .
COPY --from=builder /app/docs /root/docs

COPY .env /root/

# Открываем порт
EXPOSE 8080

# Запускаем приложение
CMD ["./todo-app"]
