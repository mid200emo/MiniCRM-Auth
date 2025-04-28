package main

import (
	"authService/pkg/logger"
	"log"

	"authService/internal/app/start"
)

func main() {
	server := start.NewServer()
	logger.Info("authService started on port 8081")
	if err := server.Run(); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
