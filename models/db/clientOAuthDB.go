package db

import (
	"github.com/go-xorm/xorm"
	"github.com/joshia/oauth2-gin-service/models/structs"
)

func InitClientOAuthQuery() *structs.ClientOAuth {
	return &structs.ClientOAuth{}
}

func UpdateClientOAuthDB(e *xorm.Engine, clientoauth *structs.ClientOAuth, clientId string, deviceId string) error {
	_, err := e.Update(clientoauth, &structs.ClientOAuth{ClientId:clientId, DeviceId:deviceId})
	if err != nil {
		return err
	}
	return nil
}

func InsertClientOAuthDB(e *xorm.Engine, clientoauth *structs.ClientOAuth) error {
	_, err := e.Insert(clientoauth)
	if err != nil {
		return err
	}
	return nil
}

func IsClientOAuthDBExist(e *xorm.Engine, clientId string, deviceId string) (bool, error) {
	var valuesMap = make(map[string]string)
	has, err := e.Table(&structs.ClientOAuth{}).Where("client_id = ? AND device_id = ?", clientId, deviceId).Get(&valuesMap)
	if err != nil {
		return false, err
	}
	return has, nil
}

func GetClientOAuthDBTimestamp(e *xorm.Engine, clientId string, deviceId string) (string, error) {
	var timestamp string
	has, err := e.Table(&structs.ClientOAuth{}).Where("client_id = ? AND device_id = ?", clientId, deviceId).Cols("timestamp").Get(&timestamp)
	if err != nil {
		return "", err
	} else if !has {
		return "", nil
	}
	return timestamp, nil
}