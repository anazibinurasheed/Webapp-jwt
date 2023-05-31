package middleware

import (
	"fmt"
	"gin-gorm-jwt/initializers"
	"gin-gorm-jwt/models"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/gin-gonic/gin"
)

func JwtAuth(c *gin.Context) {
	log.Println("<<<<Entered to middleware>>>>")
	tokenString, err := c.Cookie("Authorization")

	if err != nil {
		log.Println("No cookie recieved")
		c.Redirect(http.StatusSeeOther, "/")
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("Unexpected signing method:%v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})
	//we need to check if the token claims can be converted to a jwt.MapClaims object using a type assertion.
	//If the type assertion is successful, it means that the token claims are of type jwt.MapClaims, which is
	// a type that represents a JWT claims set as a map of string keys to arbitrary values. We can then access
	// the individual claims by key-value pairs from the claims variable, which is of type jwt.MapClaims.

	//claims of type jwt.MapClaims, which will hold the actual claims data from the token
	//ok of type bool, which will be set to true to indicate that the type assertion succeeded.
	//else false
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			log.Println("<<<<<<Token expired>>>>>>")
			c.Redirect(http.StatusSeeOther, "/")
			return
		}
		var user models.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			log.Println("<<<<<< claims[sub]  user  not found >>>>>>")

			c.Redirect(http.StatusSeeOther, "/")
			return
		}
		log.Println("<<<<<Granting access>>>>>")

		c.Next()
	} else {
		c.Redirect(http.StatusSeeOther, "/")

	}

}

func AdminJwt(c *gin.Context) {
	tokenString, err := c.Cookie("adminAuthorization")
	if err != nil {
		c.Redirect(301, "/admin")
		log.Println("no cookie recieved")
		return
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("Unexpected signing method:%v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			log.Println("<<<<<<Token expired>>>>>>")
			c.Redirect(http.StatusSeeOther, "/admin")
			return
		}

		log.Println("Granting admin access")
		c.Next()

	} else {

		c.Redirect(300, "/admin")
	}
}
