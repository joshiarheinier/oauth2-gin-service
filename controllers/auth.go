package controllers

import (
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/joshia/oauth2-gin-service/models"
	"io/ioutil"
)

func RegisterClient(c *gin.Context)  {
	appName := c.Request.Header.Get("appName")
	if res, err := models.GenerateClientSecret(appName); err != nil {
		c.JSON(500, err.Error())
	} else {
		c.JSON(200, res)
	}
}

func RequestWebToken(c *gin.Context)  {
	clientId := c.Request.Header.Get("clientId")
	deviceId := c.Request.Header.Get("deviceId")
	res, err := models.GenerateWebAuthJWT(clientId, deviceId, "web_access")
	if err != nil {
		c.JSON(500, err.Error())
	} else {
		c.JSON(200, res)
	}
}

func RequestAuthorization(c *gin.Context) {
	clientId := c.Request.Header.Get("clientId")
	deviceId := c.Request.Header.Get("deviceId")
	authToken := c.Request.Header.Get("authToken")
	if ok, err := models.VerifyAuthJWT(clientId, deviceId, authToken); ok {
		userId := c.Request.Header.Get("userId")
		scope := c.Request.Header.Get("scope")
		res, err := models.GenerateAuthCode(clientId, userId, scope)
		if err != nil {
			c.JSON(500, err.Error())
			return
		} else {
			c.JSON(200, res)
			return
		}
	} else if !ok {
		c.JSON(401, errors.New("Token is not verified").Error())
	} else if err != nil {
		c.JSON(500, err.Error())
	}
}

func RequestToken(c *gin.Context) {
	grantType := c.Request.Header.Get("grantType")
	clientId := c.Request.Header.Get("clientId")
	userId := c.Request.Header.Get("userId")
	scope := c.Request.Header.Get("scope")
	if grantType == "authorization_code" {
		authCode := c.Request.Header.Get("authCode")
		if ok, err := models.VerifyAuthCode(clientId, userId, authCode, scope); err != nil {
			c.JSON(500, err.Error())
			return
		} else if !ok {
			c.JSON(401, errors.New("Token is not verified").Error())
			return
		}
	}
	tmp := make(map[string]string)
	body, err := ioutil.ReadAll(c.Request.Body)
	json.Unmarshal(body, &tmp)
	res, err := models.GenerateAccessJWT(clientId, tmp["encrypted"], userId, scope, grantType)
	if err != nil {
		c.JSON(500, err.Error())
	} else {
		c.JSON(200, res)
	}
}