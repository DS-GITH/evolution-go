package auth_middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/EvolutionAPI/evolution-go/pkg/config"
	instance_service "github.com/EvolutionAPI/evolution-go/pkg/instance/service"
	"github.com/gin-gonic/gin"
)

type Middleware interface {
	Auth(ctx *gin.Context)
	AuthAdmin(ctx *gin.Context)
}

type middleware struct {
	config          *config.Config
	instanceService instance_service.InstanceService
}

func (m middleware) Auth(ctx *gin.Context) {
	token := ctx.GetHeader("apikey")
	if token == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
		return
	}

	instance, err := m.instanceService.GetInstanceByToken(token)
	if err != nil {
		if token == m.config.GlobalApiKey {
			instanceId := ctx.Param("instanceId")
			if instanceId == "" {
				instanceId = ctx.Query("instance")
			}

			if instanceId == "" {
				var body map[string]interface{}
				bodyBytes, _ := io.ReadAll(ctx.Request.Body)
				ctx.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				if len(bodyBytes) > 0 {
					if err := json.Unmarshal(bodyBytes, &body); err == nil {
						if inst, ok := body["instance"].(string); ok {
							instanceId = inst
						} else if instName, ok := body["instanceName"].(string); ok {
							instanceId = instName
						}
					}
				}
			}

			if instanceId != "" {
				instance, _ = m.instanceService.GetInstanceByIdOrName(instanceId)
			}
		}

		if instance == nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
			return
		}
	}

	ctx.Set("instance", instance)

	ctx.Next()
}

func (m middleware) AuthAdmin(ctx *gin.Context) {
	token := ctx.GetHeader("apikey")
	if token == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
		return
	}

	if token != m.config.GlobalApiKey {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
		return
	}

	ctx.Next()
}

func NewMiddleware(config *config.Config, instanceService instance_service.InstanceService) *middleware {
	return &middleware{config: config, instanceService: instanceService}
}
