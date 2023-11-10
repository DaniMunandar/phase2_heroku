package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	xendit "github.com/xendit/xendit-go/v3"
	invoice "github.com/xendit/xendit-go/v3/invoice"

	"gopkg.in/gomail.v2"

	"heroku/config"
	"heroku/entity"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const MaxDepositAmount = 1000000.0

type User struct {
	// Field-field dari struktur pengguna Anda disini
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type DepositData struct {
	DepositAmount float64 `json:"deposit_amount" example:"1000.00" format:"float" required:"true"`
}

// RentData adalah struktur untuk data sewa buku.
type RentData struct {
	BookID     int    `json:"book_id" example:"1" required:"true"`
	RentalDate string `json:"rental_date" example:"2023-11-09" format:"date" required:"true"`
	ReturnDate string `json:"return_date" example:"2023-11-16" format:"date" required:"true"`
}

// @Summary Register a new user
// @Description Register a new user in the system
// @Tags users
// @Accept json
// @Produce json
// @Param user body User true "User  credentials for registered"
// @Success 201 {object} map[string]interface{} "User created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 500 {object} map[string]interface{} "Failed to create user"
// @Router /users/register [post]
// RegisterUser handler untuk endpoint /users/register
func RegisterUser(c echo.Context) error {
	log := logrus.New()

	// Dapatkan data dari request
	user := new(entity.User)
	if err := c.Bind(user); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid request data")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid request data"})
	}

	// Validasi data
	validator := validator.New() // Inisialisasi validator
	if err := validator.Struct(user); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Validation error")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Validation error"})
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Error hashing password")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Error hashing password"})
	}
	user.Password = string(hashedPassword)

	// Simpan data user ke database
	db := config.DB
	if err := db.Create(&user).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to create user")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to create user"})
	}

	// Kirim email pendaftaran
	err = sendRegistrationEmail(user.Email)
	if err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to send registration email")
		// Anda dapat menangani kesalahan pengiriman email di sini
	}

	// Kirim response
	return c.JSON(http.StatusCreated, map[string]interface{}{"message": "User created successfully", "user": user})
}

func sendRegistrationEmail(recipientEmail string) error {
	log := logrus.New()
	// Konfigurasi email
	d := gomail.NewDialer("smtp.gmail.com", 587, os.Getenv("EMAIL"), os.Getenv("PASSWORD"))
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	// Membuat pesan email
	m := gomail.NewMessage()
	m.SetHeader("From", "danyoey38@gmail.com")
	m.SetHeader("To", recipientEmail)
	m.SetHeader("Subject", "Selamat bergabung!")
	m.SetBody("text/plain", "Selamat, pendaftaran Anda berhasil!")

	// Mengirim email
	if err := d.DialAndSend(m); err != nil {
		// Tangani kesalahan jika pengiriman email gagal
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to send email")
		return err
	}

	// Email terkirim dengan sukses
	return nil
}

// @Summary Login a user
// @Description Login a user and generate JWT token
// @Tags users
// @Accept json
// @Produce json
// @Param user body User true "User credentials for login"
// @Success 200 {object} map[string]interface{} "Login successful"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 401 {object} map[string]interface{} "User not found or invalid password"
// @Failure 500 {object} map[string]interface{} "Error generating token"
// @Router /users/login [post]
// LoginUser handler untuk endpoint /users/login
func LoginUser(c echo.Context) error {
	log := logrus.New()

	// Dapatkan data dari request
	requestUser := new(entity.User)
	if err := c.Bind(requestUser); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid request data")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid request data"})
	}

	// Dapatkan data user dari database berdasarkan email
	db := config.DB
	user := new(entity.User)
	if err := db.Where("email = ?", requestUser.Email).First(user).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("User not found")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "User not found"})
	}

	// Bandingkan password dengan hash yang ada di database
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(requestUser.Password))
	if err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid password")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Invalid password"})
	}

	// Generate token JWT
	token, err := generateToken(user)
	if err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Error generating token")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Error generating token"})
	}

	// Kirim response
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Login successful",
		"token":   token,
	})
}

func generateToken(user *entity.User) (string, error) {
	// Buat token JWT
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = user.ID
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	tokenString, err := token.SignedString([]byte("your-secret-key"))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Request().Header.Get("Authorization")
		if token == "" {
			return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Authorization token is required"})
		}

		claims := jwt.MapClaims{}
		jwtToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte("your-secret-key"), nil
		})

		if err != nil || !jwtToken.Valid {
			return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Invalid or expired token"})
		}

		// Jika token valid, Anda dapat melanjutkan ke handler berikutnya
		return next(c)
	}
}

// @Summary Deposit an amount to user's account
// @Description Deposit an amount to user's account and update Xendit
// @Tags users
// @Accept json
// @Produce json
// @Param Authorization header string true "JWT token"
// @Param depositData body DepositData true "Deposit amount data"
// @Success 200 {object} map[string]interface{} "Deposit successful"
// @Failure 400 {object} map[string]interface{} "Invalid request data or insufficient deposit"
// @Failure 401 {object} map[string]interface{} "Invalid or expired token"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Failure 500 {object} map[string]interface{} "Failed to update deposit amount or send deposit to Xendit"
// @Router /users/deposit [post]
// DepositAmount handler untuk endpoint /users/deposit
func DepositAmount(c echo.Context) error {
	log := logrus.New()

	// Dapatkan token dari header Authorization
	token := c.Request().Header.Get("Authorization")
	if token == "" {
		log.Error("Authorization token is required")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Authorization token is required"})
	}

	// Validasi token JWT
	claims := jwt.MapClaims{}
	jwtToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil
	})

	userId := claims["id"].(float64)

	if err != nil || !jwtToken.Valid {
		log.Error("Invalid or expired token")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Invalid or expired token"})
	}

	// Dapatkan data dari request
	depositData := struct {
		DepositAmount float32 `json:"deposit_amount"`
	}{}
	if err := c.Bind(&depositData); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid request data")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid request data"})
	}

	// Dapatkan data user dari database berdasarkan ID
	db := config.DB
	user := new(entity.User)
	if err := db.Where("id = ?", userId).First(user).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("User not found")
		return c.JSON(http.StatusNotFound, map[string]interface{}{"message": "User not found"})
	}

	// Lakukan validasi depositAmount
	if depositData.DepositAmount <= 0 {
		log.Error("Invalid deposit amount")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid deposit amount"})
	}

	// Pastikan deposit tidak melebihi batasan tertentu
	if depositData.DepositAmount > MaxDepositAmount {
		log.Error("Deposit amount exceeds maximum limit")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Deposit amount exceeds maximum limit"})
	}

	// Kirim permintaan ke API Xendit
	if err := sendDepositToXendit(c, userId, depositData.DepositAmount); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Gagal mengirim deposit ke Xendit")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Gagal mengirim deposit ke Xendit"})
	}

	// Lakukan update deposit amount pada data user
	user.DepositAmount += float64(depositData.DepositAmount)

	if err := db.Save(user).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to update deposit amount")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to update deposit amount"})
	}

	// Kirim response dengan data user yang telah diupdate
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Deposit successful",
		"user":    user,
	})
}

func sendDepositToXendit(c echo.Context, userId float64, depositAmount float32) error {
	judulInvoice := fmt.Sprintf("Invoice order user id = %v", userId)
	createInvoiceRequest := *invoice.NewCreateInvoiceRequest(judulInvoice, depositAmount)

	xenditClient := xendit.NewClient(os.Getenv("XENDIT_API_KEY"))

	resp, r, err := xenditClient.InvoiceApi.CreateInvoice(context.Background()).
		CreateInvoiceRequest(createInvoiceRequest).
		Execute()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when calling `InvoiceApi.CreateInvoice``: %v\n", err.Error())

		b, _ := json.Marshal(err.FullError())
		fmt.Fprintf(os.Stderr, "Full Error Struct: %v\n", string(b))

		fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
	}
	// response from `CreateInvoice`: Invoice
	fmt.Fprintf(os.Stdout, "Response from `InvoiceApi.CreateInvoice`: %v\n", resp)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "sukses xendit",
		"respon":  resp,
	})
}

// GetAllBooks handler untuk endpoint /books
func GetAllBooks(c echo.Context) error {
	log := logrus.New()

	// Dapatkan token dari header Authorization
	token := c.Request().Header.Get("Authorization")
	if token == "" {
		log.Error("Authorization token is required")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Authorization token is required"})
	}

	claims := jwt.MapClaims{}
	jwtToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil
	})

	if err != nil || !jwtToken.Valid {
		log.Error("Invalid or expired token")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Invalid or expired token"})
	}

	// Jika token valid, Anda dapat melanjutkan dan mengambil daftar semua buku
	db := config.DB
	var books []entity.Book
	if err := db.Find(&books).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to fetch books")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to fetch books"})
	}

	// Kirim respons dengan daftar buku
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "List of all books",
		"books":   books,
	})
}

// @Summary Get all categories
// @Description Get a list of all categories
// @Tags categories
// @Accept json
// @Produce json
// @Param Authorization header string true "JWT token"
// @Success 200 {object} map[string]interface{} "List of all categories"
// @Failure 401 {object} map[string]interface{} "Invalid or expired token"
// @Failure 500 {object} map[string]interface{} "Failed to fetch categories"
// @Router /categories [get]
// GetAllCategories handler untuk endpoint /categories
func GetAllCategories(c echo.Context) error {
	log := logrus.New()

	// Dapatkan token dari header Authorization
	token := c.Request().Header.Get("Authorization")
	if token == "" {
		log.Error("Authorization token is required")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Authorization token is required"})
	}

	claims := jwt.MapClaims{}
	jwtToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil
	})

	if err != nil || !jwtToken.Valid {
		log.Error("Invalid or expired token")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Invalid or expired token"})
	}

	// Jika token valid, Anda dapat melanjutkan dan mengambil daftar semua kategori
	db := config.DB
	var categories []entity.Category
	if err := db.Find(&categories).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to fetch categories")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to fetch categories"})
	}

	// Kirim respons dengan daftar kategori
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":    "List of all categories",
		"categories": categories,
	})
}

// @Summary Rent a book
// @Description Rent a book for a user
// @Tags books
// @Accept json
// @Produce json
// @Param Authorization header string true "JWT token"
// @Param rentData body RentData true "Rental information"
// @Success 200 {object} map[string]interface{} "Book rental successful"
// @Failure 400 {object} map[string]interface{} "Invalid request data or insufficient deposit"
// @Failure 401 {object} map[string]interface{} "Invalid or expired token"
// @Failure 404 {object} map[string]interface{} "Book not found or out of stock"
// @Failure 500 {object} map[string]interface{} "Failed to create rental history or update book stock"
// @Router /books/rent [post]
// RentBook handler untuk endpoint /books/rent
func RentBook(c echo.Context) error {
	log := logrus.New()

	// Dapatkan token dari header Authorization
	token := c.Request().Header.Get("Authorization")
	if token == "" {
		log.Error("Authorization token is required")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Authorization token is required"})
	}

	claims := jwt.MapClaims{}
	jwtToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil
	})

	userId := claims["id"].(float64)

	if err != nil || !jwtToken.Valid {
		log.Error("Invalid or expired token")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Invalid or expired token"})
	}

	// Jika token valid, Anda dapat melanjutkan proses penyewaan
	// Dapatkan data dari request
	rentData := struct {
		BookID     int    `json:"book_id"`
		RentalDate string `json:"rental_date"`
		ReturnDate string `json:"return_date"`
	}{}

	if err := c.Bind(&rentData); err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Invalid request data")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid request data"})
	}

	// Lakukan validasi data, misalnya, pastikan tanggal sewa dan tanggal kembali valid
	rentalDate, _ := time.Parse("2006-01-02", rentData.RentalDate)
	returnDate, _ := time.Parse("2006-01-02", rentData.ReturnDate)

	if err != nil {
		log.Error("Invalid date format. Please use YYYY-MM-DD format.")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid date format"})
	}

	// Hitung selisih hari antara tanggal penyewaan dan tanggal pengembalian
	days := int(returnDate.Sub(rentalDate).Hours() / 24)

	// Misalnya, biaya sewa adalah 10 unit per hari
	rentalCost := 10.0 * float64(days)

	// Pastikan biaya sewa lebih besar dari 0
	if rentalCost <= 0 {
		log.Error("Invalid rental cost")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid rental cost"})
	}

	// Simpan data riwayat sewa ke dalam database
	db := config.DB
	rental := entity.RentalHistory{
		UserID:     int(userId),
		BookID:     rentData.BookID,
		RentalDate: rentData.RentalDate,
		ReturnDate: rentData.ReturnDate,
		RentalCost: rentalCost,
	}

	if err := db.Create(&rental).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to create rental history")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to create rental history"})
	}

	// Ambil buku yang akan disewa dari database
	book := entity.Book{}

	if err := db.Where("id = ?", rentData.BookID).First(&book).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Book not found")
		return c.JSON(http.StatusNotFound, map[string]interface{}{"message": "Book not found"})
	}
	// Pastikan stok buku mencukupi
	if book.Stock <= 0 {
		log.Error("Book is out of stock")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Book is out of stock"})
	}

	// Mengurangkan stok buku yang disewa
	book.Stock--
	if err := db.Save(&book).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to update book stock")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to update book stock"})
	}

	// Menghitung deposit berdasarkan buku yang dipinjam
	depositAmount := int(rentalCost)

	// Mengurangi deposit dari akun user
	user := entity.User{}
	if err := db.Where("id = ?", int(userId)).First(&user).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("User not found")
		return c.JSON(http.StatusNotFound, map[string]interface{}{"message": "User not found"})
	}

	// Konversi tipe data depositAmount menjadi float64 jika belum
	depositAmountFloat := float64(depositAmount)

	if user.DepositAmount < depositAmountFloat {
		log.Error("Insufficient deposit")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Insufficient deposit"})
	}

	user.DepositAmount -= depositAmountFloat
	if err := db.Save(&user).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to update user deposit")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to update user deposit"})
	}

	// Kirim respons sukses
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Book rental successful",
		"rental":  rental,
	})
}

// @Summary Get rental history for a user
// @Description Get rental history for a user based on the JWT token
// @Tags users
// @Accept json
// @Produce json
// @Param Authorization header string true "JWT token"
// @Success 200 {object} map[string]interface{} "Rental history for user"
// @Failure 401 {object} map[string]interface{} "Invalid or expired token"
// @Failure 500 {object} map[string]interface{} "Failed to fetch rental history"
// @Router /users/rental-history [get]
// GetRentalHistory handler untuk endpoint /users/rental-history
func GetRentalHistory(c echo.Context) error {
	log := logrus.New()

	// Dapatkan token dari header Authorization
	token := c.Request().Header.Get("Authorization")
	if token == "" {
		log.Error("Authorization token is required")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Authorization token is required"})
	}

	claims := jwt.MapClaims{}
	jwtToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil
	})

	if err != nil || !jwtToken.Valid {
		log.Error("Invalid or expired token")
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{"message": "Invalid or expired token"})
	}

	// Dapatkan ID pengguna dari klaim token
	userID, ok := claims["id"].(float64)
	if !ok {
		log.Error("Invalid user ID in token claims")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"message": "Invalid user ID in token claims"})
	}

	// Konversi userID menjadi integer
	userIDInt := int(userID)

	// Mengambil riwayat sewa dari database berdasarkan ID pengguna
	db := config.DB
	var rentalHistory []entity.RentalHistory
	if err := db.Where("user_id = ?", userIDInt).Find(&rentalHistory).Error; err != nil {
		log.WithFields(logrus.Fields{"error": err.Error()}).Error("Failed to fetch rental history")
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"message": "Failed to fetch rental history"})
	}

	// Kirim respons dengan daftar riwayat sewa
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":       "Rental history for user",
		"rentalHistory": rentalHistory,
	})
}
