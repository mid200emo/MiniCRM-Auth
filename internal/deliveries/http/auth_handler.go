package http

import (
	"authService/internal/app/config"
	"authService/internal/app/connections"
	"authService/internal/services"
	"authService/internal/usecases"
	"authService/pkg/reqresp"
	"context"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

var authUsecase = usecases.NewAuthUsecase(services.NewAuthService(config.LoadConfig()))

func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
}

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		h(w, r)
	}
}

func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/register", withCORS(Register))
	mux.HandleFunc("/login", withCORS(Login))
	mux.HandleFunc("/refresh", withCORS(Refresh))
	mux.HandleFunc("/logout", withCORS(Logout))
}

func Register(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
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
	enableCORS(w)
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
func Logout(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(tokenString, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
		return []byte(authUsecase.JWTSecret()), nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	username := claims["username"].(string)

	ctx := context.Background()
	if err := connections.RedisClient.Del(ctx, "refresh_"+username).Err(); err != nil {
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged out successfully"))
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
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
