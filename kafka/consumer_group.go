package kafka

import (
	"context"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
)

type MConsumerGroup struct {
	topic  string
	group  sarama.ConsumerGroup
	logger *zap.Logger
}

// NewConsumerGroup создает новый Consumer Group
func NewConsumerGroup(brokers []string, topic, groupID string, logger *zap.Logger) (*MConsumerGroup, error) {
	saramaConfig := sarama.NewConfig()
	saramaConfig.Consumer.Offsets.Initial = sarama.OffsetOldest
	saramaConfig.Consumer.Return.Errors = true
	saramaConfig.Consumer.Group.Rebalance.GroupStrategies = []sarama.BalanceStrategy{sarama.NewBalanceStrategyRange()}

	group, err := sarama.NewConsumerGroup(brokers, groupID, saramaConfig)
	if err != nil {
		logger.Error("❌ Ошибка создания Consumer Group", zap.Error(err))
		return nil, err
	}

	logger.Info("✅ Подключен к Consumer Group", zap.String("groupID", groupID))

	// Отдельный процесс для логирования ошибок Consumer Group
	go func() {
		for err := range group.Errors() {
			logger.Error("🔥 Ошибка Consumer Group", zap.Error(err))
		}
	}()

	return &MConsumerGroup{
		topic:  topic,
		group:  group,
		logger: logger,
	}, nil
}

// RegisterHandlerAndConsumeMessages запускает Consumer Group
func (cg *MConsumerGroup) RegisterHandlerAndConsumeMessages(ctx context.Context, handler sarama.ConsumerGroupHandler) {
	defer cg.group.Close()

	for {
		if err := cg.group.Consume(ctx, []string{cg.topic}, handler); err != nil {
			cg.logger.Error("❌ Ошибка при получении сообщений", zap.Error(err))
			time.Sleep(2 * time.Second) // Ретрай с задержкой
		}
	}
}

// Close закрывает Consumer Group
func (cg *MConsumerGroup) Close() error {
	cg.logger.Info("🛑 Завершение работы Consumer Group")
	return cg.group.Close()
}
