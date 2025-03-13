package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type KafkaLogger struct {
	producer sarama.SyncProducer
	topic    string
}

// NewKafkaLogger создает KafkaLogger
func NewKafkaLogger(brokers []string, topic string) (*KafkaLogger, error) {
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Producer.Retry.Max = 5
	config.Producer.RequiredAcks = sarama.WaitForAll

	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka producer: %w", err)
	}

	return &KafkaLogger{producer: producer, topic: topic}, nil
}

// WriteLog отправляет лог в Kafka с полным JSON-объектом
func (kl *KafkaLogger) WriteLog(level, msg string, fields map[string]interface{}) {
	logEntry := map[string]interface{}{
		"level":     level,
		"message":   msg,
		"timestamp": time.Now().Format(time.RFC3339),
		"fields":    fields,
	}

	logJSON, err := json.Marshal(logEntry)
	if err != nil {
		fmt.Println("❌ Failed to marshal log to JSON:", err)
		return
	}

	kafkaMsg := &sarama.ProducerMessage{
		Topic: kl.topic,
		Value: sarama.ByteEncoder(logJSON),
	}

	partition, offset, err := kl.producer.SendMessage(kafkaMsg)
	if err != nil {
		fmt.Println("❌ Failed to send log to Kafka:", err)
	} else {
		fmt.Printf("✅ [Kafka Log] Sent to partition %d at offset %d\n", partition, offset)
	}
}

// Close закрывает Kafka producer
func (kl *KafkaLogger) Close() error {
	return kl.producer.Close()
}

// NewZapLogger создает zap логгер с полным стеком вызовов
func NewZapLogger(kafkaLogger *KafkaLogger) *zap.Logger {
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.CallerKey = "caller"

	logger, _ := cfg.Build(zap.AddCaller(), zap.AddStacktrace(zap.WarnLevel))

	return logger.WithOptions(zap.Hooks(func(entry zapcore.Entry) error {
		fields := map[string]interface{}{
			"caller":   entry.Caller.String(),
			"stack":    entry.Stack,
			"time":     entry.Time.Format(time.RFC3339),
			"level":    entry.Level.String(),
			"message":  entry.Message,
			"hostname": getHostname(),
			"pid":      os.Getpid(),
		}

		kafkaLogger.WriteLog(entry.Level.String(), entry.Message, fields)
		return nil
	}))
}

// Логируем HTTP-запросы с деталями
func LogRequest(log *zap.Logger, method, path, ip, userAgent string, status int, latency time.Duration) {
	log.Info("🌍 HTTP-запрос",
		zap.String("method", method),
		zap.String("path", path),
		zap.String("client_ip", ip),
		zap.String("user_agent", userAgent),
		zap.Int("status", status),
		zap.Duration("latency", latency),
	)
}

// Получаем имя хоста
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
