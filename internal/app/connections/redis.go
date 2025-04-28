package connections

import (
	"authService/internal/app/config"
	"context"
	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client

func InitRedis(cfg *config.Config) error {
	RedisClient = redis.NewClient(&redis.Options{
		Addr: cfg.RedisAddr,
	})

	ctx := context.Background()
	return RedisClient.Ping(ctx).Err()
}
