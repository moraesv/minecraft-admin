package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

var (
	adminUser string
	adminPass string
	minePath  string
	command   string
)

func main() {
	godotenv.Load()
	adminUser = os.Getenv("ADMIN_USER")
	adminPass = os.Getenv("ADMIN_PASS")
	minePath = os.Getenv("MINE_RPG_PATH")
	command = os.Getenv("MINE_START_COMMAND")

	r := gin.Default()

	// Servir arquivos estáticos (frontend)
	r.Static("/static", "./static")
	r.LoadHTMLGlob("templates/*")

	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/login")
	})

	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})

	r.GET("/dashboard", func(c *gin.Context) {
		token, _ := c.Cookie("token")
		if token != "valid" {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		c.HTML(http.StatusOK, "dashboard.html", nil)
	})

	r.POST("/api/login", login)
	r.GET("/api/server/status", authMiddleware(), serverStatus)
	r.POST("/api/server/start", authMiddleware(), serverStart)
	r.GET("/api/server/logs", authMiddleware(), serverLogs)

	r.Run(":8080")
}

func login(c *gin.Context) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	c.BindJSON(&creds)

	if creds.Username == adminUser && creds.Password == adminPass {
		c.SetCookie("token", "valid", 3600, "/", "", false, true)
		c.JSON(http.StatusOK, gin.H{"success": true})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false})
	}
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("token")
		if err != nil || token != "valid" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

func serverStatus(c *gin.Context) {
	out, _ := exec.Command("bash", "-c", "screen -list | grep mine").Output()
	status := "off"
	if strings.Contains(string(out), "mine") {
		status = "running"
	}
	c.JSON(http.StatusOK, gin.H{"status": status})
}

func serverStart(c *gin.Context) {
	// Verificar se o processo já está rodando
	out, _ := exec.Command("bash", "-c", "screen -list | grep mine").Output()
	if strings.Contains(string(out), "mine") {
		c.JSON(http.StatusOK, gin.H{"message": "Servidor já está em execução"})
		return
	}

	cmd := `cd "` + minePath + `" && screen -dmS mine bash -c '` + command + ` > server.log 2>&1'`
	fmt.Println(cmd)
	outLog, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   err.Error(),
			"details": string(outLog),
		})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "Servidor iniciado e logs sendo gravados em server.log"})
	}
}

func serverLogs(c *gin.Context) {
	logPath := minePath + "/server.log"
	content, err := os.ReadFile(logPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Não foi possível ler o log"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"log": string(content)})
}
