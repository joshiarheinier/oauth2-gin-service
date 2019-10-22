package structs

type ClientCredential struct {
	ClientId		string	`json:"clientId"`
	ClientSecret	string	`json:"clientSecret"`
} 

type ClientOAuth struct {
	ClientId	string	`json:"clientId"`
	DeviceId	string	`json:"deviceId"`
	Timestamp	string	`json:"timestamp"`
}

type UserOAuth struct {
	UserId			string	`json:"userId"`
	ClientId		string	`json:"clientId"`
	Scope			string	`json:"scope"`
	AuthCode		string	`json:"authCode"`
	Timestamp		string	`json:"timestamp"`
	RefreshToken	string `json:"refreshToken"`
}
