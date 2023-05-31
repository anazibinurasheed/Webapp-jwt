package main

import (
	"gin-gorm-jwt/controllers"
	"gin-gorm-jwt/initializers"
	"gin-gorm-jwt/middleware"

	"github.com/gin-gonic/gin"
)

func init() {

	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()

}

func main() {

	router := gin.Default()
	router.Static("/static", "./static")

	// User
	router.GET("/", controllers.LoginPage)
	router.GET("/home", middleware.JwtAuth, controllers.Home)
	router.POST("/", controllers.LoginSubmit)
	router.GET("/signup" ,middleware.JwtAuth, controllers.SignUp)
	router.POST("/signup", controllers.SignUpSubmit)
	router.GET("/signout", controllers.Signout)


	//Admin
	router.GET("/admin", controllers.AdminLogin)
	router.POST("/adminpanel", controllers.AdminPanel)
	router.GET("/users", middleware.AdminJwt, controllers.ViewUsers)
	//users route only need the middleware
	router.GET("/admin/edit_user/:id", middleware.AdminJwt, controllers.EditUser)
	router.POST("/admin/create_user", middleware.AdminJwt, controllers.Create_User)
	router.POST("/admin/edit_user", middleware.AdminJwt, controllers.EditPage)
	router.GET("/admin/delete_user/:id", middleware.AdminJwt, controllers.Delete_user)
	router.GET("/adminsignout", controllers.AdminLogout)
	router.POST("/search", middleware.AdminJwt, controllers.Search)
	router.GET("/search", middleware.AdminJwt, controllers.SearchResult)
	//
	router.Run()

}
