package logger

import (
	"log"
	"os"
	"time"
)

func InitLogger() {
	logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	log.SetOutput(logFile)
	log.SetFlags(0)
}
func Info(msg string) {
	log.Printf("[INFO] %s: %s\n", time.Now().Format(time.RFC3339), msg)
}

func Error(msg string, err error) {
	log.Printf("[ERROR] %s: %s | error: %v\n", time.Now().Format(time.RFC3339), msg, err)
}
