package http

import (
	"authService/internal/app/config"
	"authService/internal/services"
	"authService/internal/usecases"
	"authService/pkg/reqresp"
	"encoding/json"
	"errors"
	"net/http"
)

var authUsecase = usecases.NewAuthUsecase(services.NewAuthService(config.LoadConfig()))

func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/register", Register)
	mux.HandleFunc("/login", Login)
	mux.HandleFunc("/refresh", Refresh)
}

func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req reqresp.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := authUsecase.Register(req.Username, req.Password, req.Role, req.Email)
	if err != nil {
		if errors.Is(err, services.ErrUserAlreadyExists) {
			http.Error(w, "User already exists", http.StatusConflict)
		} else {
			http.Error(w, "Failed to register user", http.StatusInternalServerError)
		}
		return
	}

	json.NewEncoder(w).Encode(reqresp.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req reqresp.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := authUsecase.Login(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			http.Error(w, "User not found", http.StatusUnauthorized)
		} else if errors.Is(err, services.ErrInvalidPassword) {
			http.Error(w, "Invalid password", http.StatusUnauthorized)
		} else {
			http.Error(w, "Login failed", http.StatusInternalServerError)
		}
		return
	}

	json.NewEncoder(w).Encode(reqresp.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := authUsecase.Refresh(req.RefreshToken)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(reqresp.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
