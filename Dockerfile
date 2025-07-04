FROM golang:1.22-alpine AS builder

WORKDIR /app

# Копируем сначала только файлы модулей для кэширования
COPY go.mod go.sum ./
RUN go mod download

# Копируем остальные файлы
COPY . .

# Собираем приложение
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/testjunior ./cmd/main.go

# Финальный образ
FROM alpine:latest

WORKDIR /app

# Копируем бинарник и скрипты
COPY --from=builder /app/testjunior .
COPY --from=builder /app/wait-for-postgres.sh .
RUN chmod +x wait-for-postgres.sh

# Устанавливаем зависимости
RUN apk add --no-cache postgresql-client

EXPOSE 8080

COPY .env .
COPY configs/ /app/configs/
CMD ["./wait-for-postgres.sh", "db", "./testjunior"]