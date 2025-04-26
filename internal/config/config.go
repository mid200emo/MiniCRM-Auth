package config

import (
	"os"
)

type Config struct {
	Port      string
	DbURL     string
	JwtSecret string
}

func LoadConfig() *Config {
	return &Config{
		Port:      getEnv("AUTH_SERVICE_PORT", "8081"),
		DbURL:     getEnv("AUTH_SERVICE_DB_URL", "postgres://user:password@localhost:5432/authdb?sslmode=disable"),
		JwtSecret: getEnv("AUTH_SERVICE_JWT_SECRET", "secret"),
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
