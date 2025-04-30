package usecases

import (
	"authService/internal/services"
)

type AuthUsecase struct {
	authService *services.AuthService
}

func NewAuthUsecase(authService *services.AuthService) *AuthUsecase {
	return &AuthUsecase{authService: authService}
}

func (uc *AuthUsecase) Register(username, password, role, email string) (accessToken, refreshToken string, err error) {
	return uc.authService.Register(username, password, role, email)
}

func (uc *AuthUsecase) Login(username, password string) (accessToken, refreshToken string, err error) {
	return uc.authService.Login(username, password)
}

func (uc *AuthUsecase) Refresh(refreshToken string) (accessToken, newRefreshToken string, err error) {
	return uc.authService.RefreshTokens(refreshToken)
}
func (uc *AuthUsecase) JWTSecret() string {
	return uc.authService.JWTSecret()
}
