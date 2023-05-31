package controllers

import (
	"gin-gorm-jwt/helper"
	"gin-gorm-jwt/models"
	"log"
	"net/http"
	"os"
	"time"

	"gin-gorm-jwt/initializers"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var editId string

// Load the admin page
func AdminLogin(c *gin.Context) {
	c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")
	
	Tpl = helper.ParseHtml("adminLogin.html")
	Tpl.ExecuteTemplate(c.Writer, "adminLogin.html", nil)

}

// Validate the admin and if valid give access
func AdminPanel(c *gin.Context) {
	c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")
	Email := c.PostForm("Email")
	Password := c.PostForm("Password")
	adminEmail := os.Getenv("ADMIN_EMAIL")
	adminPass := os.Getenv("ADMIN_PASS")
	log.Println(adminEmail, adminPass)

	if adminEmail != Email || adminPass != Password {
		Tpl = helper.ParseHtml("adminLogin.html")
		TplMessage.Message = "Invalid email address or password "
		Tpl.ExecuteTemplate(c.Writer, "adminLogin.html", TplMessage)
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "Admin",
		"exp": time.Now().Add(time.Minute * 30).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		log.Println("Error while creating jwt >>>>>>")
	}
	maxAge := time.Minute * 30
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("adminAuthorization", tokenString, int(maxAge.Seconds()), "", "", false, true)
	log.Println("<<<<set cookiedone on admin side>>>>")

	c.Redirect(301, "/users")
}

func EditUser(c *gin.Context) {
	c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")

	editId = c.Param("id")
	log.Println("<<<<<<<<<<<<", editId, ">>>>>>>>>>>>>>>>>>")
	var user models.User
	initializers.DB.First(&user, "id = ?", editId)
	Tpl = helper.ParseHtml("editPage.html")
	Tpl.ExecuteTemplate(c.Writer, "editPage.html", user)

}

func EditPage(c *gin.Context) {
	Username := c.PostForm("Username")
	Email := c.PostForm("Email")
	Password := c.PostForm("Password")

	var user models.User

	initializers.DB.Find(&user, editId)
	if Username != "" {
		user.Username = Username
	}
	if Email != "" {
		user.Email = Email

	}
	if Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(Password), 10)
		if err != nil {
			log.Fatal("error while editing password ", err)
		}
		user.Password = string(hash)

	}

	initializers.DB.Save(&user)
	c.Redirect(301,"/users")

}

func Delete_user(c *gin.Context) {
	c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")

	id := c.Param("id")
	log.Println("<<<<<<<<<<<<<", id, ">>>>>>>>>>>>")
	var user models.User
	initializers.DB.Delete(&user, id)
	log.Println(user)
	c.SetCookie("Authorization", "", -1, "", "", false, true)
	log.Println("its done")
c.Redirect(301,"/users")
}
func Create_User(c *gin.Context) {
	c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")

	Username := c.PostForm("Username")
	Email := c.PostForm("Email")
	Password := c.PostForm("Password")

	if Username == "" && Email == "" {
		c.Redirect(301, "/users")
	}
	log.Println(Username, Email, Password, ">>>><<<<<")

	result := initializers.DB.Find(&TplMessage.Users)
	if result.Error != nil {

		log.Println("<<<<>>>>>>", result.RowsAffected)
		c.AbortWithStatus(500)
		log.Fatal("<<<<<<Error when retreiving all object from db>>>>>>>>", result.Error)
		return
	}

	if helper.EmailValidation(Email) != true {
		TplMessage.Message = "Please enter a valid email address"
		Tpl = helper.ParseHtml("errorMessageAdmin.html")
		Tpl.ExecuteTemplate(c.Writer, "errorMessageAdmin.html", TplMessage)
		return

	}
	var user models.User

	initializers.DB.Where("username = ?", Username).First(&user)

	if user.Username == Username {
		TplMessage.Message = "Sorry, that username is already taken. Please choose a different username."
		Tpl = helper.ParseHtml("errorMessageAdmin.html")
		Tpl.ExecuteTemplate(c.Writer, "errorMessageAdmin.html", TplMessage)
		return

	}

	initializers.DB.Where("Email = ?", Email).First(&user)

	if user.Email == Email {
		log.Println("<<<Entered to email check>>>")
		TplMessage.Message = "An account with this email address already exists.Please try login or use a different email address to create a new account"
		Tpl = helper.ParseHtml("errorMessageAdmin.html")
		Tpl.ExecuteTemplate(c.Writer, "errorMessageAdmin.html", TplMessage)
		return

	}

	//the 10 representing 10 rounds of hashing its the dafault cost also,
	//if the cost is higher the hash will become more secure but the computation time will increase .
	hash, err := bcrypt.GenerateFromPassword([]byte(Password), 10)

	if err != nil {
		log.Fatal(">>>Error while hashing<<<", err)
	}

	createUser := models.User{Username: Username, Email: Email, Password: string(hash)}
	result = initializers.DB.Create(&createUser)
	if result.Error != nil {

		TplMessage.Message = "Unable to process your request right now ,please try again later"
		Tpl = helper.ParseHtml("errorMessageAdmin.html")
		Tpl.ExecuteTemplate(c.Writer, "errorMessageAdmin.html", TplMessage)
		return
	}
	log.Println("User created  -------Name-------", Username, "-------Email-------", Email)
	c.Redirect(301, "/users")
}

func ViewUsers(c *gin.Context) {
	// _, err := c.Cookie("adminAuthorization")
	// if err != nil {
	// 	c.Redirect(303, "/admin")
	// }
	result := initializers.DB.Raw("select * from users  order by id offset 5 fetch first 5 rows only ").Find(&TplMessage.Users)
	if result.Error != nil {

		log.Println("<<<<>>>>>>", result.RowsAffected)
		c.AbortWithStatus(500)
		log.Fatal("<<<<<<Error when retreiving all object from db >>>>>>>>", result.Error)
		return
	}

	Tpl = helper.ParseHtml("adminPanel.html")
	Tpl.ExecuteTemplate(c.Writer, "adminPanel.html", TplMessage)

}
func AdminLogout(c *gin.Context) {
	c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")

	c.SetCookie("adminAuthorization", "", -1, "", "", false, true)
	c.Redirect(http.StatusSeeOther, "/admin")
}

var search string

func Search(c *gin.Context) {
	c.Header("Cache-Control", "no-store,no-cache,max-age=0")
	_, err := c.Cookie("adminAuthorization")
	if err != nil {
		c.Redirect(303, "/admin")
		return
	}

	search = c.PostForm("search")
	search = search + "%"
	if search == "%" {
		c.Redirect(301, "/users")
		return
	}
	log.Println("<<<<from search func :search ->>>>>>>", search)
	c.Redirect(303, "/search")

}

func SearchResult(c *gin.Context) {
	c.Header("Cache-Control", "no-store,no-cache,max-age=0")
	_, err := c.Cookie("adminAuthorization")
	if err != nil {
		c.Redirect(303, "/admin")
		return
	}
	errorMsg := Text{}
	var user models.User
	log.Println("func searchresult : search <<<<>>>>", search)
	result := initializers.DB.Raw("select * from users where username ilike ? fetch first 1 row only", search).Scan(&user)
	log.Printf("user : :::: %#v,%#v", user.Username, user.ID)
	if result.Error != nil {
		log.Println("Error while retreiving the searched user  stage one  ")
		
		// errorMsg.Message = "User not found "
		// Tpl=helper.ParseHtml("errorMessageAdmin.html")
		// Tpl.ExecuteTemplate(c.Writer, "errorMessageAdmin.html", errorMsg)
		return
	}
	if user.ID == 0 {
		errorMsg.Message = "User not found "
		Tpl=helper.ParseHtml("errorMessageAdmin.html")
		Tpl.ExecuteTemplate(c.Writer, "errorMessageAdmin.html", errorMsg)
		return
	}
	SearchResult := Text{}
	result = initializers.DB.Raw("select * from users where username ilike ? order by id", search).Find(&SearchResult.Users)
	if result.Error != nil {
		log.Println("Error while retreiving the searched user  stage two")

		log.Fatal("Error while retreving all user data")
	}
	Tpl=helper.ParseHtml("adminPanel.html")
	Tpl.ExecuteTemplate(c.Writer, "adminPanel.html", SearchResult)

}
