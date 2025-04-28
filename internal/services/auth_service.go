package services

import (
	"authService/internal/app/connections"
	"authService/pkg/logger"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"

	"authService/internal/app/config"
	"github.com/golang-jwt/jwt/v5"
)

type AuthService struct {
	cfg *config.Config
}

var (
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidPassword   = errors.New("invalid password")
)

func NewAuthService(cfg *config.Config) *AuthService {
	return &AuthService{cfg: cfg}
}
func (s *AuthService) JWTSecret() string {
	return s.cfg.JWTSecret
}

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Password string `json:"password,omitempty"`
}

func (s *AuthService) Register(username, password, role, email string) (string, string, error) {
	userReq := map[string]string{
		"username": username,
		"email":    email,
		"role":     role,
		"password": password,
	}
	body, _ := json.Marshal(userReq)

	resp, err := http.Post("http://user-service:8082/users", "application/json", bytes.NewBuffer(body))
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", "", errors.New("failed to create user")
	}
	logger.Info("new user registered: " + username)
	return s.GenerateTokens(username, role)
}

func (s *AuthService) Login(username, password string) (string, string, error) {
	// Используем кэшированное получение пользователя
	user, err := s.getUserByUsername(username)
	if err != nil {
		logger.Error("user login failed", err)
		return "", "", ErrUserNotFound
	}

	// Проверяем пароль через bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		logger.Error("user login failed", err)
		return "", "", ErrInvalidPassword
	}
	logger.Info("user login successful: " + username)
	// Генерируем токены
	return s.GenerateTokens(user.Username, user.Role)
}

func (s *AuthService) getUserByUsername(username string) (*User, error) {
	ctx := context.Background()
	cacheKey := fmt.Sprintf("user_username_%s", username)

	// 1. Пытаемся найти в кэше
	cachedUserJSON, err := connections.RedisClient.Get(ctx, cacheKey).Result()
	if err == nil {
		var cachedUser User
		if jsonErr := json.Unmarshal([]byte(cachedUserJSON), &cachedUser); jsonErr == nil {
			return &cachedUser, nil
		}
	}

	// 2. Если не нашли в кэше, идём в userService
	url := fmt.Sprintf("http://user-service:8082/users/by-username/%s", username)
	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, ErrUserNotFound
	}
	defer resp.Body.Close()

	var user User
	if decodeErr := json.NewDecoder(resp.Body).Decode(&user); decodeErr != nil {
		return nil, fmt.Errorf("failed to decode userService response")
	}

	// 3. Кладём в Redis
	userBytes, _ := json.Marshal(user)
	_ = connections.RedisClient.Set(ctx, cacheKey, userBytes, 5*time.Minute).Err()

	return &user, nil
}

func (s *AuthService) GenerateTokens(username, role string) (accessToken string, refreshToken string, err error) {
	accessTokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(time.Minute * 15).Unix(), // 15 минут
	})

	accessTokenString, err := accessTokenClaims.SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		return "", "", err
	}

	refreshTokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(time.Hour * 24 * 7).Unix(), // 7 дней
	})

	refreshTokenString, err := refreshTokenClaims.SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		return "", "", err
	}

	ctx := context.Background()
	_ = connections.RedisClient.Set(ctx, "refresh_"+username, refreshTokenString, 7*24*time.Hour).Err()

	return accessTokenString, refreshTokenString, nil
}
func (s *AuthService) RefreshTokens(refreshToken string) (string, string, error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.cfg.JWTSecret), nil
	})

	if err != nil || !token.Valid {
		return "", "", errors.New("invalid refresh token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", errors.New("invalid token claims")
	}

	username, _ := claims["username"].(string)
	role, _ := claims["role"].(string)

	ctx := context.Background()
	savedToken, err := connections.RedisClient.Get(ctx, "refresh_"+username).Result()
	if err != nil || savedToken != refreshToken {
		return "", "", errors.New("refresh token mismatch")
	}

	// Генерируем новые токены
	accessToken, newRefreshToken, err := s.GenerateTokens(username, role)
	if err != nil {
		return "", "", err
	}

	return accessToken, newRefreshToken, nil
}
