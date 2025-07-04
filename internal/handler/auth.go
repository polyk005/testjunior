package handler

import (
	"fmt"
	"net/http"
	"testjunior/internal/model"

	"github.com/gin-gonic/gin"
)

func (h *Handler) SignUp(c *gin.Context) {
	var input model.User

	if err := c.BindJSON(&input); err != nil {
		newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	id, err := h.services.Authorization.CreateUser(input)
	if err != nil {
		newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"id": id,
	})
}

type SignInInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *Handler) SignIn(c *gin.Context) {
	var input SignInInput

	if err := c.BindJSON(&input); err != nil {
		newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	token, err := h.services.Authorization.GenerateToken(input.Username, input.Password)
	if err != nil {
		newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"token": token,
	})
}

// Получение пары токенов по user_id
func (h *Handler) GetTokenPair(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		newErrorResponse(c, http.StatusBadRequest, "user_id required")
		return
	}
	// user_id должен быть int
	var id int
	_, err := fmt.Sscanf(userID, "%d", &id)
	if err != nil {
		newErrorResponse(c, http.StatusBadRequest, "invalid user_id")
		return
	}
	ua := c.GetHeader("User-Agent")
	ip := c.ClientIP()
	access, refresh, err := h.services.Authorization.GenerateTokenPair(id, ua, ip)
	if err != nil {
		newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]string{
		"access":  access,
		"refresh": refresh,
	})
}

type RefreshInput struct {
	Refresh string `json:"refresh" binding:"required"`
}

func (h *Handler) RefreshTokenPair(c *gin.Context) {
	var input RefreshInput
	if err := c.BindJSON(&input); err != nil {
		newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}
	ua := c.GetHeader("User-Agent")
	ip := c.ClientIP()
	access, refresh, err := h.services.Authorization.RefreshTokenPair(input.Refresh, ua, ip)
	if err != nil {
		newErrorResponse(c, http.StatusUnauthorized, err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]string{
		"access":  access,
		"refresh": refresh,
	})
}

func (h *Handler) GetMe(c *gin.Context) {
	header := c.GetHeader("Authorization")
	if header == "" {
		newErrorResponse(c, http.StatusUnauthorized, "empty auth header")
		return
	}
	var token string
	fmt.Sscanf(header, "Bearer %s", &token)
	if token == "" {
		newErrorResponse(c, http.StatusUnauthorized, "invalid auth header")
		return
	}
	userID, err := h.services.Authorization.ParseToken(token)
	if err != nil {
		newErrorResponse(c, http.StatusUnauthorized, err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"user_id": userID})
}

type LogoutInput struct {
	Refresh string `json:"refresh" binding:"required"`
}

func (h *Handler) Logout(c *gin.Context) {
	var input LogoutInput
	if err := c.BindJSON(&input); err != nil {
		newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	// Используйте методы сервиса вместо прямого доступа к repo
	err := h.services.Authorization.DeactivateRefreshTokenByValue(input.Refresh)
	if err != nil {
		newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, map[string]string{"status": "logout"})
}
