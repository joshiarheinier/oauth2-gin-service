package structs

import "github.com/dgrijalva/jwt-go"

type AuthClaims struct {
	ClientId string `json:"clientId"`
	DeviceId string `json:"deviceId"`
	jwt.StandardClaims
}

type AccessClaims struct {
	UserId		string	`json:"userId"`
	ClientId	string	`json:"clientId"`
	Scope		string	`json:"scope"`
	jwt.StandardClaims
}
