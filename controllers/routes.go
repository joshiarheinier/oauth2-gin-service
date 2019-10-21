package controllers

import (
	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	r.POST("/v1/oauth/register/client", RegisterClient)
	r.POST("/v1/oauth/init", RequestWebToken)
	r.POST("/v1/oauth/request/authorization", RequestAuthorization)
	r.POST("/v1/oauth/request/token", RequestToken)
}
