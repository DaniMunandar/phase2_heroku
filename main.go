package main

import (
	"heroku/config"
	"heroku/docs"
	"heroku/handler"

	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"

	_ "github.com/joho/godotenv/autoload"
)

func main() {
	e := echo.New()

	// Inisialisasi dokumen Swagger
	docs.SwaggerInfo.Title = "LIBRARY BOOKS"
	docs.SwaggerInfo.Description = "API for Books Rent"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.BasePath = ""

	e.GET("/swagger/*", echoSwagger.WrapHandler)

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	config.InitDB()

	e.POST("/users/register", handler.RegisterUser)
	e.POST("/users/login", handler.LoginUser)

	e.POST("/users/deposit", handler.DepositAmount, handler.AuthMiddleware)

	e.GET("/books", handler.GetAllBooks, handler.AuthMiddleware)
	e.GET("/categories", handler.GetAllCategories, handler.AuthMiddleware)

	e.POST("/books/rent", handler.RentBook, handler.AuthMiddleware)

	e.GET("/history", handler.GetRentalHistory, handler.AuthMiddleware)

	port := os.Getenv("PORT")
	e.Logger.Fatal(e.Start(":" + port))
}
