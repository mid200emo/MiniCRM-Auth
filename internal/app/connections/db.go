package connections

import (
	"authService/internal/app/config"
	"authService/internal/data"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB(cfg *config.Config) error {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		cfg.DBHost, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBPort)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	// 🛠 Добавляем авто-миграцию таблицы User
	err = DB.AutoMigrate(&data.User{})
	if err != nil {
		return err
	}

	return nil
}
