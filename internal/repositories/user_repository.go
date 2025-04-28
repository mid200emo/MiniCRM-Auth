package repositories

import (
	"authService/internal/app/connections"
	"authService/internal/data"
)

type UserRepository struct{}

func NewUserRepository() *UserRepository {
	return &UserRepository{}
}

func (r *UserRepository) Create(user *data.User) error {
	return connections.DB.Create(user).Error
}

func (r *UserRepository) FindByUsername(username string) (*data.User, error) {
	var user data.User
	result := connections.DB.Where("username = ?", username).First(&user)
	return &user, result.Error
}
