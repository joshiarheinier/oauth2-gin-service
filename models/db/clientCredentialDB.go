package db

import (
	"github.com/go-xorm/xorm"
	"github.com/joshia/oauth2-gin-service/models/structs"
)

func InitClientCredentialQuery() *structs.ClientCredential {
	return &structs.ClientCredential{}
}

func UpdateClientCredentialDB(e *xorm.Engine, clientcredential *structs.ClientCredential, clientId string, clientSecret string) error {
	_, err := e.Update(clientcredential, &structs.ClientCredential{ClientId:clientId, ClientSecret:clientSecret})
	if err != nil {
		return err
	}
	return nil
}

func InsertClientCredentialDB(e *xorm.Engine, clientcredential *structs.ClientCredential) error {
	_, err := e.Insert(clientcredential)
	if err != nil {
		return err
	}
	return nil
}

func IsClientCredentialDBExist(e *xorm.Engine, clientId string, args...string) (bool, error) {
	var valuesMap = make(map[string]string)
	var has bool
	var err error
	if args != nil {
		has, err = e.Table(&structs.ClientCredential{}).Where("client_id = ? AND client_secret = ?", clientId, args[0]).Get(&valuesMap)
	} else {
		has, err = e.Table(&structs.ClientCredential{}).Where("client_id = ?", clientId).Get(&valuesMap)

	}
	if err != nil {
		return false, err
	}
	return has, nil
}

func GetClientCredentialDB(e *xorm.Engine, clientId string) (*structs.ClientCredential, error) {
	var clientcredential structs.ClientCredential
	has, err := e.Table(&structs.ClientCredential{}).Where("client_id = ?", clientId).Get(&clientcredential)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, nil
	}
	return &clientcredential, nil
}