package connections

import (
	"log"

	"github.com/jmoiron/sqlx"
	//"github.com/lib/pq"
	"github.com/xydownik/MiniCRM/mini-crm/auth-service/internal/config"
)

func ConnectDB(cfg *config.Config) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", cfg.DbURL)
	if err != nil {
		return nil, err
	}
	log.Println("Подключено к БД")
	return db, nil
}
