package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

var (
	adminUser string
	adminPass string
	minePath  string
	javaCmd   string
)

func main() {
	godotenv.Load()
	adminUser = os.Getenv("ADMIN_USER")
	adminPass = os.Getenv("ADMIN_PASS")
	minePath = os.Getenv("MINE_RPG_PATH")
	javaCmd = os.Getenv("JAVA_COMMAND")

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
	r.GET("/mods", func(c *gin.Context) {
		token, _ := c.Cookie("token")
		if token != "valid" {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		c.HTML(http.StatusOK, "mods.html", nil)
	})
	r.GET("/teleport", func(c *gin.Context) {
		token, _ := c.Cookie("token")
		if token != "valid" {
			c.Redirect(http.StatusFound, "/login")
			return
		}
		c.HTML(http.StatusOK, "teleport.html", nil)
	})

	r.POST("/api/login", login)
	r.GET("/api/server/status", authMiddleware(), serverStatus)
	r.POST("/api/server/start", authMiddleware(), serverStart)
	r.GET("/api/server/logs", authMiddleware(), serverLogs)
	r.GET("/api/mods", authMiddleware(), listMods)
	r.POST("/api/mods/upload", authMiddleware(), uploadMod)
	r.POST("/api/mods/disable", authMiddleware(), disableMod)
	r.POST("/api/command/tp", authMiddleware(), teleportCommand)

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

	cmd := `cd "` + minePath + `" && screen -dmS mine bash -c '` + javaCmd + ` > server.log 2>&1'`
	outLog, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   err.Error(),
			"details": string(outLog),
		})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "Servidor iniciado e logs sendo gravados em server.log"})
	}
}

func serverLogs(c *gin.Context) {
	logPath := filepath.Join(minePath, "server.log")
	content, err := os.ReadFile(logPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Não foi possível ler o log"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"log": string(content)})
}

func listMods(c *gin.Context) {
	modsDir := filepath.Join(minePath, "mods")
	files, err := os.ReadDir(modsDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao ler a pasta mods"})
		return
	}

	modNames := []string{}
	for _, f := range files {
		if !f.IsDir() {
			modNames = append(modNames, f.Name())
		}
	}

	c.JSON(http.StatusOK, gin.H{"mods": modNames})
}

func uploadMod(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Arquivo não fornecido"})
		return
	}

	savePath := filepath.Join(minePath, "mods", filepath.Base(file.Filename))
	err = c.SaveUploadedFile(file, savePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao salvar o arquivo"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Arquivo enviado com sucesso"})
}

func disableMod(c *gin.Context) {
	var req struct {
		ModName string `json:"mod"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Requisição inválida"})
		return
	}

	source := filepath.Join(minePath, "mods", req.ModName)
	destDir := filepath.Join(minePath, "mods_old")
	os.MkdirAll(destDir, 0755)
	dest := filepath.Join(destDir, req.ModName)

	err := os.Rename(source, dest)
	if err != nil {
		fmt.Println(req)
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao mover o arquivo"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Mod inativado com sucesso"})
}

func teleportCommand(c *gin.Context) {
	var req struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := c.BindJSON(&req); err != nil || req.From == "" || req.To == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parâmetros inválidos"})
		return
	}

	cmd := "screen -S mine -X stuff \"/tp " + req.From + " " + req.To + "\\r\""
	err := exec.Command("bash", "-c", cmd).Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Falha ao executar comando"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Comando de teleporte executado"})
}
