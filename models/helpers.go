package models

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"github.com/go-xorm/xorm"
	"github.com/joshia/oauth2-gin-service/models/db"
	"math/rand"
	"strings"
	"time"
)

func updateClientAuthorizationDB(e *xorm.Engine, clientId string, deviceId string, timestamp string) error {
	has, err := db.IsClientOAuthDBExist(e, clientId, deviceId)
	if err != nil {
		return err
	}
	clientoauth := db.InitClientOAuthQuery()
	clientoauth.ClientId = clientId
	clientoauth.DeviceId = deviceId
	clientoauth.Timestamp = timestamp
	if has {
		return db.UpdateClientOAuthDB(e, clientoauth, clientId, deviceId)
	}
	return db.InsertClientOAuthDB(e, clientoauth)
}

func updateUserAccessDB() error {
	db.InitUserOAuthQuery()
	return nil
}

func getClientKeyDB(e *xorm.Engine, clientId string, deviceId string) (string, error) {
	key, err := db.GetClientOAuthDBTimestamp(e, clientId, deviceId)
	if err != nil {
		return "", err
	} else if key == "" {
		return key, errors.New("Client does not exist in DB")
	}
	return key, nil
}

func updateUserAuthorizationDB(e *xorm.Engine, clientId string, userId string, scope string, authCode string, timestamp string, refToken string) error {
	has, err := db.IsUserOAuthDBExist(e, clientId, userId, scope)
	if err != nil {
		return err
	}
	useroauth := db.InitUserOAuthQuery()
	useroauth.ClientId = clientId
	useroauth.UserId = userId
	useroauth.Scope = scope
	useroauth.AuthCode = authCode
	useroauth.Timestamp = timestamp
	useroauth.RefreshToken = refToken
	if has {
		return db.UpdateUserOAuthDB(e, useroauth, clientId, userId, scope)
	}
	return db.InsertUserOAuthDB(e, useroauth)
}

func generateClientSecret() string {
	randomStr := sha512.Sum512([]byte(generateRandomString()))
	return hex.EncodeToString(randomStr[:])
}

func generateRandomString() string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖ" +
		"abcdefghijklmnopqrstuvwxyzåäö" +
		"0123456789")
	length := 8
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}