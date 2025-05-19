package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
)

var (
	adminUser string
	adminPass string
	minePath  string
	javaCmd   string
	jwtSecret []byte
)

func main() {
	godotenv.Load()
	adminUser = os.Getenv("ADMIN_USER")
	adminPass = os.Getenv("ADMIN_PASS")
	minePath = os.Getenv("MINE_PATH")
	javaCmd = os.Getenv("JAVA_COMMAND")
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))

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
	r.GET("/dashboard", authRequired(), func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", nil)
	})
	r.GET("/mods", authRequired(), func(c *gin.Context) {
		c.HTML(http.StatusOK, "mods.html", nil)
	})
	r.GET("/teleport", authRequired(), func(c *gin.Context) {
		c.HTML(http.StatusOK, "teleport.html", nil)
	})
	r.GET("/logout", authRequired(), func(c *gin.Context) {
		c.HTML(http.StatusOK, "logout.html", nil)
	})

	r.POST("/api/login", login)
	r.POST("/api/logout", logout)
	r.GET("/api/server/status", authMiddleware(), serverStatus)
	r.POST("/api/server/start", authMiddleware(), serverStart)
	r.POST("/api/server/stop", authMiddleware(), serverStop)
	r.GET("/api/server/logs", authMiddleware(), serverLogs)
	r.GET("/api/server/difficulty", authMiddleware(), getDifficulty)
	r.GET("/api/mods", authMiddleware(), listMods)
	r.POST("/api/mods/upload", authMiddleware(), uploadMod)
	r.POST("/api/mods/disable", authMiddleware(), disableMod)
	r.POST("/api/command/tp", authMiddleware(), teleportCommand)
	r.POST("/api/command/difficulty", authMiddleware(), alterDifficulty)

	r.Run(":8080")
}

func login(c *gin.Context) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&creds); err != nil {
		log.Println("Erro ao ler credenciais:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Dados inválidos"})
		return
	}

	if creds.Username == adminUser && creds.Password == adminPass {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": creds.Username,
			"exp":      time.Now().Add(time.Hour * 1).Unix(),
		})

		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			log.Println("Erro ao gerar token:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao gerar token"})
			return
		}

		c.SetCookie("token", tokenString, 3600, "/", "", false, true)
		c.JSON(http.StatusOK, gin.H{"success": true})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false})
	}
}

func logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logout realizado com sucesso"})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("token")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token não encontrado"})
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrInvalidKeyType
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token inválido"})
			return
		}

		c.Next()
	}
}

func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("token")
		if err != nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
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

func serverStop(c *gin.Context) {
	out, err := exec.Command("bash", "-c", "screen -list | grep mine").Output()
	if !strings.Contains(string(out), "mine") {
		c.JSON(http.StatusOK, gin.H{"message": "Servidor já está parado"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao consultar status do servidor"})
		return
	}

	err = exec.Command("screen", "-S", "mine", "-X", "quit").Run()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao parar o servidor"})
		return
	} else {
		time.Sleep(2 * time.Second)
		c.JSON(http.StatusOK, gin.H{"message": "Servidor está sendo desligado"})
	}
}

func serverLogs(c *gin.Context) {
	logPath := filepath.Join(minePath, "server.log")
	content, err := os.ReadFile(logPath)
	if err != nil {
		log.Println("Erro ao ler o log:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Não foi possível ler o log"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"log": string(content)})
}

func listMods(c *gin.Context) {
	modsDir := filepath.Join(minePath, "mods")
	files, err := os.ReadDir(modsDir)
	if err != nil {
		log.Println("Erro ao ler a pasta mods:", err)
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
		log.Println("Erro ao obter o arquivo:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Arquivo não fornecido"})
		return
	}

	savePath := filepath.Join(minePath, "mods", filepath.Base(file.Filename))
	err = c.SaveUploadedFile(file, savePath)
	if err != nil {
		log.Println("Erro ao salvar o arquivo:", err)
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
		log.Println("Erro ao mover o arquivo:", err)
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

func alterDifficulty(c *gin.Context) {
	var req struct {
		Level string `json:"level"` // "easy", "normal" ou "hard"
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Formato inválido"})
		return
	}

	validLevels := map[string]bool{"easy": true, "normal": true, "hard": true}
	if !validLevels[req.Level] {
		log.Println("Dificuldade inválida:", req.Level)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Dificuldade inválida"})
		return
	}

	log.Println("Alterando dificuldade para:", req.Level)

	// Comando para enviar para o screen
	cmdStr := fmt.Sprintf("/difficulty %s", req.Level)
	cmd := exec.Command("screen", "-S", "mine", "-X", "stuff", cmdStr+"\r")

	if err := cmd.Run(); err != nil {
		log.Println("Erro ao executar comando:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao enviar comando"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Dificuldade alterada para " + req.Level})
}

func getDifficulty(c *gin.Context) {
	logPath := filepath.Join(minePath, "server.log")

	// Envia o comando para o Minecraft
	cmd := exec.Command("screen", "-S", "mine", "-X", "stuff", "/difficulty\r")
	if err := cmd.Run(); err != nil {
		log.Println("Erro ao executar comando:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao executar comando"})
		return
	}

	// Espera um pouco para o log ser escrito
	time.Sleep(1 * time.Second)

	// Lê o log
	content, err := os.ReadFile(logPath)
	if err != nil {
		log.Println("Erro ao ler o log:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao ler log"})
		return
	}

	// Procura pela linha que contém "The difficulty is "
	lines := strings.Split(string(content), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if strings.Contains(line, "The difficulty is ") {
			// Exemplo: "...The difficulty is Easy"
			parts := strings.Split(line, "The difficulty is ")
			if len(parts) > 1 {
				difficulty := strings.TrimSpace(parts[1])
				c.JSON(http.StatusOK, gin.H{"difficulty": difficulty})
				return
			}
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Não foi possível encontrar a dificuldade no log"})
}
