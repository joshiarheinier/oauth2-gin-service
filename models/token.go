package models

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/joshia/oauth2-gin-service/config"
	"github.com/joshia/oauth2-gin-service/models/db"
	"github.com/joshia/oauth2-gin-service/models/structs"
	"time"
)

var secret_key  = "secret"

func GenerateClientSecret(appName string) (*structs.RegisteredResponse, error) {
	engine := config.NewDBEngine()
	clientcredential := db.InitClientCredentialQuery()
	clientcredential.ClientId = appName
	clientcredential.ClientSecret =generateClientSecret()
	if err := db.InsertClientCredentialDB(engine, clientcredential); err != nil {
		return nil, err
	}
	regisRes := &structs.RegisteredResponse{
		Status:       "REGISTERED",
		ClientId:     clientcredential.ClientId,
		ClientSecret: clientcredential.ClientSecret,
	}
	return regisRes, nil
}

func VerifyClient(clientId string, clientSecret string) (bool, error) {
	engine := config.NewDBEngine()
	if has, err := db.IsClientCredentialDBExist(engine, clientId, clientSecret); !has {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func GenerateWebAuthJWT(clientId string, deviceId string, grantType string) (*structs.JWTWebResponse, error) {
	engine := config.NewDBEngine()
	if has, err := db.IsClientCredentialDBExist(engine, clientId); !has {
		return nil, errors.New("Client is not authorized")
	} else if err != nil {
		return nil, err
	}
	claims := &structs.AuthClaims{
		ClientId: clientId,
		DeviceId: deviceId,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
		},
	}
	jwtRes := &structs.JWTWebResponse{
		Type:	grantType,
		Token:	"",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	timestamp := time.Now().String()
	jwt, err := token.SignedString([]byte(secret_key+timestamp))
	if err != nil {
		return nil, err
	}
	jwtRes.Token = jwt
	if err := updateClientAuthorizationDB(engine, clientId, deviceId, timestamp); err != nil {
		return nil, err
	}
	return jwtRes, nil
}

func GenerateAccessJWT(clientId string, userId string, authCode string, grantType string) (*structs.JWTResourceResponse, error) {
	engine := config.NewDBEngine()
	var codeCol string
	if grantType == "authorization_code" {
		codeCol = "auth_code"
	} else if grantType == "refresh_token" {
		codeCol = "refresh_token"
	}
	useroauth, err := db.GetUserOAuthDBByCode(engine, clientId, userId, authCode, codeCol)
	claims := &structs.AccessClaims{
		ClientId: useroauth.ClientId,
		UserId: useroauth.UserId,
		Scope: useroauth.Scope,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		},
	}
	refClaims := &structs.AccessClaims{
		ClientId: useroauth.ClientId,
		UserId: useroauth.UserId,
		Scope: "refresh",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
		},
	}
	jwtRes := &structs.JWTResourceResponse{
		Type:	grantType,
		Token:	"",
		RefreshToken: "",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	refToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refClaims)
	timestamp := time.Now().String()
	jwt, err := token.SignedString([]byte(secret_key+timestamp))
	refjwt, err := refToken.SignedString([]byte(secret_key+timestamp))
	if err != nil {
		return nil, err
	}
	jwtRes.Token = jwt
	jwtRes.RefreshToken = refjwt
	 if err := updateUserAuthorizationDB(engine, useroauth.ClientId, useroauth.UserId, useroauth.Scope, "expired", timestamp, refjwt); err != nil {
	 	return nil, err
	 }
	return jwtRes, nil
}

func VerifyAuthJWT(clientId string, deviceId string, authToken string) (bool, error) {
	engine := config.NewDBEngine()
	timestamp, err := getClientKeyDB(engine, clientId, deviceId)
	if err != nil {
		return false, err
	}
	claims := &structs.AuthClaims{}
	token, err := jwt.ParseWithClaims(authToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret_key+timestamp), nil
	})
	if err != nil {
		return false, err
	} else if !token.Valid {
		return false, nil
	}
	return true, nil
}

func GenerateAuthCode(clientId string, userId string, scope string) (*structs.AuthorizedResponse, error) {
	engine := config.NewDBEngine()
	authCode := generateRandomString()
	err := updateUserAuthorizationDB(engine, clientId, userId, scope, authCode, "", "")
	if err != nil {
		return nil, err
	}
	authRes := &structs.AuthorizedResponse{
		Status:   "SUCCESS",
		AuthCode: authCode,
	}
	return authRes, nil
}

func VerifyAuthCode(clientId string, userId string, authCode string) (bool, error) {
	engine := config.NewDBEngine()
	useroauth, err := db.GetUserOAuthDBByCode(engine, clientId, userId, authCode, "auth_code")
	if err != nil {
		return false, err
	} else if useroauth == nil {
		return false, errors.New("User has either not authorized or been authorized")
	}
	return true, nil
}

func VerifyRefreshToken(clientId string, userId string, refToken string) (bool, error) {
	engine := config.NewDBEngine()
	useroauth, err := db.GetUserOAuthDBByCode(engine, clientId, userId, refToken, "refresh_token")
	if err != nil {
		return false, err
	} else if useroauth == nil {
		return false, errors.New("User does not have refresh token")
	}
	claims := &structs.AuthClaims{}
	token, err := jwt.ParseWithClaims(refToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret_key+useroauth.Timestamp), nil
	})
	if err != nil {
		return false, err
	} else if !token.Valid {
		return false, nil
	}
	return true, nil
}