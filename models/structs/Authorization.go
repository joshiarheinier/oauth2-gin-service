package structs

type AuthorizedResponse struct {
	Status		string	`json:"status"`
	AuthCode	string	`json:"auth_code"`
}

type JWTWebResponse struct {
	Type	string	`json:"type"`
	Token	string	`json:"token"`
}

type JWTResourceResponse struct {
	Type			string	`json:"type"`
	Token			string	`json:"token"`
	RefreshToken	string	`json:"refreshToken"`
}

type RegisteredResponse struct {
	Status		string	`json:"status"`
	ClientId	string	`json:"clientId"`
	ClientSecret	string	`json:"clientSecret"`
}