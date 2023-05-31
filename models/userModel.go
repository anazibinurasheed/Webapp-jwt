package models


type User struct {
	ID        uint `gorm:"primarykey"`
	Username string
	Email    string 
	Password string
}
