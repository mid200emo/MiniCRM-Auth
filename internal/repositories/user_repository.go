package repositories

import (
	"github.com/jmoiron/sqlx"
	"github.com/xydownik/MiniCRM/mini-crm/auth-service/pkg/domain"
)

// UserRepository управляет операциями с пользователями
type UserRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CreateUser(user *domain.User) error {
	_, err := r.db.NamedExec("INSERT INTO users (email, password, created_at) VALUES (:email, :password, :created_at)", user)
	return err
}

func (r *UserRepository) GetUserByEmail(email string) (*domain.User, error) {
	var user domain.User
	err := r.db.Get(&user, "SELECT * FROM users WHERE email = $1", email)
	return &user, err
}
