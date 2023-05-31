package initializers

import (
	"gin-gorm-jwt/models"
	"log"
)

func SyncDatabase() {

	err := DB.AutoMigrate(&models.User{})
	if err != nil {
		log.Fatal("Failed to create table")
	}
}
