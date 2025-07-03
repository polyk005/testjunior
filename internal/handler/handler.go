package handler

import (
	"testjunior/internal/service"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	services *service.Service
}

func NewHandler(services *service.Service) *Handler {
	return &Handler{services: services}
}

func (h *Handler) InitRoutes() *gin.Engine {
	router := gin.New()

	auth := router.Group("/auth")
	{
		auth.POST("/sign-in", h.SignIn)
		auth.POST("/sign-up", h.SignUp)
		auth.GET("/token", h.GetTokenPair)
		auth.POST("/refresh", h.RefreshTokenPair)
		auth.GET("/me", h.GetMe)
		auth.POST("/logout", h.Logout)
	}

	return router
}
