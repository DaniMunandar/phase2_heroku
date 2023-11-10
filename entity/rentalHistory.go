package entity

type RentalHistory struct {
	ID         int     `json:"id"`
	UserID     int     `json:"user_id"`
	BookID     int     `json:"book_id"`
	RentalDate string  `json:"rental_date"`
	ReturnDate string  `json:"return_date"`
	RentalCost float64 `json:"rental_cost"`
}
