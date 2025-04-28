package start

import (
	"authService/internal/app/config"
	"authService/internal/app/connections"
	delivery "authService/internal/deliveries/http"
	"fmt"
	"net/http"
)

type Server struct {
	cfg *config.Config
}

func NewServer() *Server {
	cfg := config.LoadConfig()
	return &Server{cfg: cfg}
}

func (s *Server) Run() error {
	if err := connections.InitDB(s.cfg); err != nil {
		return err
	}
	if err := connections.InitRedis(s.cfg); err != nil {
		return err
	}

	router := http.NewServeMux()
	delivery.RegisterRoutes(router)

	addr := fmt.Sprintf(":%s", s.cfg.ServerPort)
	return http.ListenAndServe(addr, router)
}
