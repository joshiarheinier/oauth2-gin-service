package db

import (
	"github.com/go-xorm/xorm"
	"github.com/joshia/oauth2-gin-service/models/structs"
)

func InitUserOAuthQuery() *structs.UserOAuth {
	return &structs.UserOAuth{}
}

func UpdateUserOAuthDB(e *xorm.Engine, useroauth *structs.UserOAuth, clientId string, userId string, scope string) error {
	_, err := e.Update(useroauth, &structs.UserOAuth{ClientId:clientId, UserId:userId, Scope:scope})
	if err != nil {
		return err
	}
	return nil
}

func InsertUserOAuthDB(e *xorm.Engine, useroauth *structs.UserOAuth) error {
	_, err := e.Insert(useroauth)
	if err != nil {
		return err
	}
	return nil
}

func IsUserOAuthDBExist(e *xorm.Engine, clientId string, userId string, scope string) (bool, error) {
	var valuesMap = make(map[string]string)
	has, err := e.Table(&structs.UserOAuth{}).Where("client_id = ? AND user_id = ? AND scope = ?", clientId, userId, scope).Get(&valuesMap)
	if err != nil {
		return false, err
	}
	return has, nil
}

func GetUserOAuthDB(e *xorm.Engine, clientId string, userId string, scope string) (*structs.UserOAuth, error) {
	var useroauth structs.UserOAuth
	has, err := e.Table(&structs.UserOAuth{}).Where("client_id = ? AND user_id = ? AND scope = ?", clientId, userId, scope).Get(&useroauth)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, nil
	}
	return &useroauth, nil
}