package controllers

import (
	"gin-gorm-jwt/helper"
	"gin-gorm-jwt/initializers"
	"gin-gorm-jwt/models"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

var Tpl *template.Template

type Text struct {
	Username string
	Message  string
	Users    []models.User
}

var TplMessage = Text{}

func LoginPage(c *gin.Context) {
	c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")

	_, err := c.Cookie("Authorization")
	if err == nil {
		c.Redirect(http.StatusSeeOther, "/home")
		return
	}
	Tpl = helper.ParseHtml("login.html")

	Tpl.ExecuteTemplate(c.Writer, "login.html", nil)

}

func SignUp(c *gin.Context) {
  _,err:=c.Cookie("Authorization")
  if err == nil{
	c.Redirect(303,"/home")
	return
  }


	c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")

	Tpl = helper.ParseHtml("signup.html")
	Tpl.ExecuteTemplate(c.Writer, "signup.html", nil)
}

func SignUpSubmit(c *gin.Context) {
	Username := c.PostForm("Username")
	Email := c.PostForm("Email")
	Password := c.PostForm("Password")
	Repassword := c.PostForm("Repassword")
	log.Println(Username, Email, Password, ">>>><<<<<")

	if helper.EmailValidation(Email) != true {
		TplMessage.Message = "Please enter a valid email address"
		Tpl = helper.ParseHtml("signup.html")
		Tpl.ExecuteTemplate(c.Writer, "signup.html", TplMessage)
		return

	}
	var user models.User

	initializers.DB.Where("username = ?", Username).First(&user)

	if user.Username == Username {
		TplMessage.Message = "Sorry, that username is already taken. Please choose a different username."
		Tpl = helper.ParseHtml("signup.html")
		Tpl.ExecuteTemplate(c.Writer, "signup.html", TplMessage)
		return

	}

	initializers.DB.Where("Email = ?", Email).First(&user)

	if user.Email == Email {
		log.Println("<<<Entered to email check>>>")
		TplMessage.Message = "An account with this email address already exists.Please try login or use a different email address to create a new account"
		Tpl = helper.ParseHtml("signup.html")
		Tpl.ExecuteTemplate(c.Writer, "signup.html", TplMessage)
		return

	}

	if Password != Repassword {

		// c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")
		TplMessage.Message = " password mismatch. Please try again."

		Tpl = helper.ParseHtml("signup.html")
		log.Println("Password doesnt match<<<>>>")
		Tpl.ExecuteTemplate(c.Writer, "signup.html", TplMessage)
		return
	}

	//the 10 representing 10 rounds of hashing its the dafault cost also,
	//if the cost is higher the hash will become more secure but the computation time will increase .
	hash, err := bcrypt.GenerateFromPassword([]byte(Password), 10)

	if err != nil {
		log.Fatal(">>>Error while hashing<<<", err)
	}

	createUser := models.User{Username: Username, Email: Email, Password: string(hash)}
	result := initializers.DB.Create(&createUser)
	if result.Error != nil {

		c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")
		TplMessage.Message = "Unable to process your request right now ,please try again later"
		Tpl = helper.ParseHtml("signup.html")
		Tpl.ExecuteTemplate(c.Writer, "signup.html", TplMessage)
		return
	}
	log.Println("User created  -------Name-------", Username, "-------Email-------", Email)
	c.Redirect(http.StatusFound, "/")

}

func LoginSubmit(c *gin.Context) {

	//Look up requested user
	Email := c.PostForm("Email")
	Password := c.PostForm("Password")

	var user models.User
	initializers.DB.First(&user, "Email = ?", Email)

	//If user not found in db compose a  message
	if user.ID == 0 {

		c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")
		TplMessage.Message = "Dont have an account with this email"
		Tpl = helper.ParseHtml("login.html")
		Tpl.ExecuteTemplate(c.Writer, "login.html", TplMessage)
		return
	}

	//compare sent in pass with saved user pass hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(Password))
	// if the password is wrong compose a message
	if err != nil {

		c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")

		TplMessage.Message = "please enter correct password "
		Tpl = helper.ParseHtml("login.html")
		Tpl.ExecuteTemplate(c.Writer, "login.html", TplMessage)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		// "exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		log.Println("<<<<<<<Error while creating jwt>>>>>>")
	}
	c.SetSameSite(http.SameSiteLaxMode)
	maxAge := time.Minute * 5

	c.SetCookie("Authorization", tokenString, int(maxAge.Seconds()), "", "", false, true)
	// 3600*24*30
	log.Println("<<<<set cookie done>>>>>>>")

	c.Redirect(http.StatusSeeOther, "/home")
	// Tpl = helper.ParseHtml("index.html")
	// Tpl.ExecuteTemplate(c.Writer, "index.html", "welcome back")

}
func Home(c *gin.Context) {
	c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")
	Tpl = helper.ParseHtml("index.html")
	Tpl.ExecuteTemplate(c.Writer, "index.html", "welcome back")
}
func Signout(c *gin.Context) {

	c.Header("Cache-Control", "must-revalidate,no-store,no-cache,max-age=0")

	c.SetCookie("Authorization", "", -1, "", "", false, true)
	c.Redirect(http.StatusFound, "/")
}
