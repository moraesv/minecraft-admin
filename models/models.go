package models

type Location struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Nickname string `gorm:"unique;not null" json:"nickname"`
	Target   string `gorm:"not null" json:"target"`
}
