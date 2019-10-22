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
	var code string
	tmp := make(map[string]string)
	body, err := ioutil.ReadAll(c.Request.Body)
	json.Unmarshal(body, &tmp)
	if ok, err := models.VerifyClient(clientId, tmp["encrypted"]); err != nil {
		c.JSON(500, err.Error())
	} else if !ok {
		c.JSON(401, errors.New("Client is not authorized").Error())
	}
	if grantType == "authorization_code" {
		code = c.Request.Header.Get("authCode")
		if ok, err := models.VerifyAuthCode(clientId, userId, code); err != nil {
			c.JSON(500, err.Error())
			return
		} else if !ok {
			c.JSON(401, errors.New("Token is not verified").Error())
			return
		}
	} else if grantType == "refresh_token" {
		code = c.Request.Header.Get("refreshToken")
		if ok, err := models.VerifyRefreshToken(clientId, userId, code); err != nil {
			c.JSON(500, err.Error())
			return
		} else if !ok {
			c.JSON(401, errors.New("Token is not verified").Error())
			return
		}
	}
	res, err := models.GenerateAccessJWT(clientId, userId, code, grantType)
	if err != nil {
		c.JSON(500, err.Error())
	} else {
		c.JSON(200, res)
	}
}