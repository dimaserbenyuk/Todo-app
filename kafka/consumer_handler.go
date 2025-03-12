package kafka

import (
	"encoding/json"
	"fmt"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
)

type ConsumerHandler struct {
	Logger *zap.Logger
}

// Setup выполняется перед началом потребления нового набора сообщений
func (h *ConsumerHandler) Setup(_ sarama.ConsumerGroupSession) error {
	h.Logger.Info("🚀 Consumer Group инициализирован")
	return nil
}

// Cleanup вызывается при завершении обработки
func (h *ConsumerHandler) Cleanup(_ sarama.ConsumerGroupSession) error {
	h.Logger.Info("🛑 Consumer Group завершил работу")
	return nil
}

// ConsumeClaim получает сообщения от Kafka
func (h *ConsumerHandler) ConsumeClaim(sess sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	fmt.Println("🟢 Consumer начал обработку сообщений!")

	for msg := range claim.Messages() {
		// Получаем заголовки (если есть)
		headers := map[string]string{}
		for _, header := range msg.Headers {
			headers[string(header.Key)] = string(header.Value)
		}

		// Логируем подробную информацию
		h.Logger.Info("📩 Получено сообщение",
			zap.String("topic", msg.Topic),
			zap.Int32("partition", msg.Partition),
			zap.Int64("offset", msg.Offset),
			zap.String("key", string(msg.Key)),
			zap.String("value", string(msg.Value)),
			zap.Any("headers", headers),
			zap.Time("timestamp", msg.Timestamp),
		)

		// Логируем отдельно IP-адрес (если он есть в заголовках Kafka)
		if ip, exists := headers["client_ip"]; exists {
			h.Logger.Info("🌍 IP-адрес клиента", zap.String("client_ip", ip))
		}

		// Логируем отдельно статус (если он есть в JSON-сообщении)
		var jsonData map[string]interface{}
		if err := json.Unmarshal(msg.Value, &jsonData); err == nil {
			if status, exists := jsonData["status"]; exists {
				h.Logger.Info("🟢 Статус задачи", zap.Any("status", status))
			}
		}

		// Подтверждаем обработку сообщений
		sess.MarkMessage(msg, "")
	}
	return nil
}
