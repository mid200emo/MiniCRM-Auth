package deliveries

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/xydownik/MiniCRM/mini-crm/auth-service/internal/config"
	"github.com/xydownik/MiniCRM/mini-crm/auth-service/internal/repositories"
	"github.com/xydownik/MiniCRM/mini-crm/auth-service/internal/services"
	"github.com/xydownik/MiniCRM/mini-crm/auth-service/pkg/reqresp"
)

func SetupRouter(db *sqlx.DB, cfg *config.Config) *mux.Router {
	r := mux.NewRouter()

	userRepo := repositories.NewUserRepository(db)
	authService := services.NewAuthService(userRepo, cfg.JwtSecret)

	r.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var req reqresp.AuthRequest
		json.NewDecoder(r.Body).Decode(&req)
		user, err := authService.RegisterUser(req.Email, req.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(user)
	}).Methods("POST")

	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var req reqresp.AuthRequest
		json.NewDecoder(r.Body).Decode(&req)
		token, err := authService.LoginUser(req.Email, req.Password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}).Methods("POST")

	return r
}
