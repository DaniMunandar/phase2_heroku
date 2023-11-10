package entity

type Book struct {
	ID              int    `json:"id"`
	Title           string `json:"title"`
	Author          string `json:"author"`
	PublicationYear int    `json:"publication_year"`
	CategoryID      int    `json:"category_id"`
	Stock           int    `json:"stock"`
}
