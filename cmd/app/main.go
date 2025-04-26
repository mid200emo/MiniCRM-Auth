package main

import (
	"log"
	"net/http"

	"github.com/xydownik/MiniCRM/mini-crm/auth-service/internal/config"
	"github.com/xydownik/MiniCRM/mini-crm/auth-service/internal/connections"
	"github.com/xydownik/MiniCRM/mini-crm/auth-service/internal/deliveries"
)

func main() {
	cfg := config.LoadConfig()

	db, err := connections.ConnectDB(cfg)
	if err != nil {
		log.Fatalf("Ошибка подключения к БД: %v", err)
	}

	router := deliveries.SetupRouter(db, cfg)
	log.Println("Auth Service запущен на порту", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, router))
}
