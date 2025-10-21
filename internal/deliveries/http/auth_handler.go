package http

import (
	"authService/internal/app/config"
	"authService/internal/app/connections"
	"authService/internal/services"
	"authService/internal/usecases"
	"authService/pkg/reqresp"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"mime"
	"net/http"
	"strings"
	"time"
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

type claimsStd struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func parseAccessToken(raw string) (*claimsStd, error) {
	token, err := jwt.ParseWithClaims(raw, &claimsStd{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(authUsecase.JWTSecret()), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	c, ok := token.Claims.(*claimsStd)
	if !ok {
		return nil, errors.New("invalid claims")
	}
	return c, nil
}
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/register", withCORS(Register))
	mux.HandleFunc("/login", withCORS(Login))
	mux.HandleFunc("/refresh", withCORS(Refresh))
	mux.HandleFunc("/logout", withCORS(Logout))
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt, _, _ := mime.ParseMediaType(ct)
		if mt != "application/json" {
			http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
			return false
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func validUsername(s string) bool { return len(s) >= 3 && len(s) <= 64 }
func validPassword(s string) bool { return len(s) >= 8 && len(s) <= 128 }

func Register(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req reqresp.RegisterRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !validUsername(req.Username) || !validPassword(req.Password) || req.Email == "" {
		http.Error(w, "invalid fields", http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := authUsecase.Register(req.Username, req.Password, req.Role, req.Email)
	if err != nil {
		http.Error(w, "registration failed", http.StatusConflict)
		return
	}

	writeJSON(w, http.StatusOK, reqresp.AuthResponse{
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
	if !decodeJSON(w, r, &req) {
		return
	}
	if !validUsername(req.Username) || !validPassword(req.Password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	accessToken, refreshToken, err := authUsecase.Login(req.Username, req.Password)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	writeJSON(w, http.StatusOK, reqresp.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
func Logout(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authz := r.Header.Get("Authorization")
	parts := strings.SplitN(authz, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		http.Error(w, "invalid authorization header", http.StatusUnauthorized)
		return
	}

	c, err := parseAccessToken(parts[1])
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := connections.RedisClient.Del(ctx, "refresh_"+c.Username).Err(); err != nil {
		http.Error(w, "failed to logout", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("logged out"))
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
	if !decodeJSON(w, r, &req) || req.RefreshToken == "" {
		return
	}

	accessToken, refreshToken, err := authUsecase.Refresh(req.RefreshToken)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, reqresp.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
