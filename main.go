package main

import (
	"github.com/gin-gonic/gin"
	"github.com/joshia/oauth2-gin-service/controllers"
)

func main()  {
	r := gin.Default()

	controllers.SetupRoutes(r)

	// Listen and Server in 0.0.0.0:8183
	r.Run(":8880")
}
