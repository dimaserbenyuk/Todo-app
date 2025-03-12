package logger

import (
	"encoding/json"
	"fmt"
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

// WriteLog отправляет лог-сообщение в Kafka
func (kl *KafkaLogger) WriteLog(level, msg string, fields map[string]interface{}) {
	logEntry := map[string]interface{}{
		"level":     level,
		"message":   msg,
		"timestamp": time.Now().Format(time.RFC3339),
		"fields":    fields,
	}

	logJSON, _ := json.Marshal(logEntry)

	kafkaMsg := &sarama.ProducerMessage{
		Topic: kl.topic,
		Value: sarama.ByteEncoder(logJSON),
	}

	partition, offset, err := kl.producer.SendMessage(kafkaMsg)
	if err != nil {
		fmt.Println("Failed to send log to Kafka:", err)
	} else {
		fmt.Printf("[Kafka Log] Sent to partition %d at offset %d\n", partition, offset)
	}
}

// Close закрывает Kafka producer
func (kl *KafkaLogger) Close() error {
	return kl.producer.Close()
}

// NewZapLogger создает zap логгер с хуком на Kafka
func NewZapLogger(kafkaLogger *KafkaLogger) *zap.Logger {
	zapLogger := zap.NewExample()

	return zapLogger.WithOptions(zap.Hooks(func(entry zapcore.Entry) error {
		kafkaLogger.WriteLog(entry.Level.String(), entry.Message, nil)
		return nil
	}))
}
