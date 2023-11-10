package entity

type User struct {
	ID            int     `json:"id"`
	Email         string  `json:"email" validate:"required"`
	Password      string  `json:"password" validate:"required"`
	DepositAmount float64 `json:"deposit_amount"`
}
