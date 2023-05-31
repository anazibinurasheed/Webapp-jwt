package helper

import (
	"html/template"
	"log"
)

// concacinate the path string with predifined root path and parse
func ParseHtml(path string) *template.Template {
	tpl, err := template.ParseFiles("templates/" + path)
	if err != nil {
		log.Fatal("Failed to parse html file >>>", err)
	}
	

	return tpl
}

func EmailValidation(Email string) bool {
	domain := Email[len(Email)-4:]
	log.Println(">>>", domain, "<<<")
	if domain == ".com" || domain == ".net" || domain == ".org" || domain == ".edu" || domain == ".gov" || domain == ".mil" {
		return true
	}
	log.Println("<<<<trying to access without a valid domain name>>>>")
	return false
}
