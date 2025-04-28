package logger

import (
	"log"
	"time"
)

func Info(msg string) {
	log.Printf("[INFO] %s: %s\n", time.Now().Format(time.RFC3339), msg)
}

func Error(msg string, err error) {
	log.Printf("[ERROR] %s: %s | error: %v\n", time.Now().Format(time.RFC3339), msg, err)
}
