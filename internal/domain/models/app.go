package models

type App struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Secret string `json:"secret"`
}
