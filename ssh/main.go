package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Address   string `json:"ssh_listen_addr"`
	RunMode   string `json:"run_mode"`
	ImageName string `json:"image_name"`
}

type Credentials struct {
	DEV_DB_STR  string `json:"DEV_DATABASE_STRING"`
	PROD_DB_STR string `json:"PROD_DATABASE_STRING"`
}

var db *sql.DB
var creds Credentials
var cfg Config

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func handleSession(s ssh.Session) {

	emailPattern := s.User() + "@%"

	query := `
		SELECT container_name
		FROM users
		WHERE users.email LIKE ?
		LIMIT 1;
	`
	// Execute the query
	var containerName string
	err := db.QueryRow(query, emailPattern).Scan(&containerName)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Error retrieving user data: %v", err)
		} else {
			log.Fatalf("Error executing query! %v", err)
		}
		return
	}

	cmd := exec.Command(
		"/usr/bin/podman",
		"run",
		"--rm",
		"-it",
		"--replace",
		"--name", containerName,
		cfg.ImageName,
	)
	ptyReq, winCh, isPty := s.Pty()
	if isPty {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		f, err := pty.Start(cmd)
		if err != nil {
			panic(err)
		}
		go func() {
			for win := range winCh {
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			io.Copy(f, s) // stdin
		}()
		io.Copy(s, f) // stdout
		cmd.Wait()
	} else {
		io.WriteString(s, "No PTY requested.\n")
		s.Exit(1)
	}
}

func handlePublicKey(ctx ssh.Context, key ssh.PublicKey) bool {
	fmt.Printf("User: %s, Address: %s\n", ctx.User(), ctx.RemoteAddr().String())

	emailPattern := ctx.User() + "@%"

	query := `
		SELECT ssh_key 
		FROM ssh_creds 
		JOIN users ON ssh_creds.user_id = users.id 
		WHERE users.email LIKE ?
	`

	var pubKeyStr string
	if db == nil {
		log.Fatal("Database connection is nil")
	}
	err := db.QueryRow(query, emailPattern).Scan(&pubKeyStr)
	fmt.Println(pubKeyStr)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Authentication failed for user: %s (no record found)\n", ctx.User())
			return false
		}
		log.Printf("Database error during authentication: %v\n", err)
		return false
	}

	PubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil {
		log.Printf("Authentication failure for user: %s (error parsing key), %v\n", ctx.User(), err)
		return false
	}

	keyRes := ssh.KeysEqual(key, PubKey)
	if !keyRes {
		log.Printf("Authentication failure for user: %s (key mismatch)\n", ctx.User())
	}

	log.Printf("Authentication success for user: %s\n", ctx.User())
	return keyRes
}

// Return true to accept password and false to deny
func handlePassword(ctx ssh.Context, passwd string) bool {

	fmt.Printf("User: %s, Address: %s\n", ctx.User(), ctx.RemoteAddr().String())
	emailPattern := ctx.User() + "@%"

	query := `
		SELECT hashed_password 
		FROM ssh_creds 
		JOIN users ON ssh_creds.user_id = users.id 
		WHERE users.email LIKE ?
	`

	var hashedPassword string
	if db == nil {
		log.Fatal("Database connection is nil")
	}
	err := db.QueryRow(query, emailPattern).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Authentication failed for user: %s (no record found)\n", ctx.User())
			return false
		}
		log.Printf("Database error during authentication: %v\n", err)
		return false
	}

	// Verify the password using bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(passwd)); err != nil {
		log.Printf("Authentication failed for user: %s (password mismatch)\n", ctx.User())
		return false
	}

	log.Printf("Authentication succeeded for user: %s\n", ctx.User())
	return true

}

func parseJSONFile(filepath string, dest interface{}) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", filepath, err)
	}
	defer file.Close()

	// Read the entire file into a byte slice
	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filepath, err)
	}

	// Unmarshal the JSON data into the provided destination struct
	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("failed to unmarshal JSON from file %s: %w", filepath, err)
	}

	return nil
}

// ConvertMySQLURL converts a MySQL URL in one format to another
func ConvertMySQLURL(input string) (string, error) {
	// Parse the input URL
	parsedURL, err := url.Parse(input)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %v", err)
	}

	// Extract components from the input URL
	user := parsedURL.User.Username()
	password, _ := parsedURL.User.Password()
	host := parsedURL.Host
	path := strings.TrimPrefix(parsedURL.Path, "/") // Remove the leading '/'
	queryParams := parsedURL.Query()

	// Define the components for the new URL format
	var newURL string

	// Check if the original URL uses a Unix socket
	if unixSocket := queryParams.Get("unix_socket"); unixSocket != "" {
		// Format for Unix socket connection (using the extracted username and password)
		newURL = fmt.Sprintf("%s:%s@unix(%s)/%s?loc=Local", user, password, unixSocket, path)
	} else {
		// If no Unix socket, fallback to using the host
		newURL = fmt.Sprintf("%s:%s@tcp(%s)/%s?loc=Local", user, password, host, path)
	}

	return newURL, nil
}

func main() {
	// Define flags for the JSON files
	credFile := flag.String("credentials", "", "Path to the credentials JSON file")
	configFile := flag.String("config", "", "Path to the config JSON file")
	flag.Parse()

	// Ensure both files are provided
	if *credFile == "" || *configFile == "" {
		log.Fatalf("Usage: %s -credentials <credentials.json> -config <config.json>", os.Args[0])
	}

	// Parse the credentials JSON file
	if err := parseJSONFile(*credFile, &creds); err != nil {
		log.Fatalf("Failed to parse credentials file: %v", err)
	}

	// Parse the config JSON file
	if err := parseJSONFile(*configFile, &cfg); err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	var db_str string
	if cfg.RunMode == "dev" {
		db_str = creds.DEV_DB_STR
	} else {
		db_str = creds.PROD_DB_STR
	}
	var connection_str string
	var driver string
	var err error
	if strings.HasPrefix(db_str, "sqlite://") {
		// Remove the "sqlite://" prefix and get the file path
		filePath := strings.TrimPrefix(db_str, "sqlite://")
		// Prepend "file:" to match the desired format
		connection_str = "file:instance/" + filePath
		driver = "sqlite3"
	} else if strings.HasPrefix(db_str, "mysql://") {
		connection_str, err = ConvertMySQLURL(db_str)
		if err != nil {
			log.Fatal(err)
		}
		driver = "mysql"
	}
	db, err = sql.Open(driver, connection_str)

	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	// Verify the database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Database connection is not active: %v", err)
	}

	log.Println("Database initialized successfully")
	defer db.Close()

	s := &ssh.Server{
		Addr:             cfg.Address,
		Handler:          handleSession,
		PasswordHandler:  handlePassword,
		PublicKeyHandler: handlePublicKey,
		IdleTimeout:      360 * time.Second,
	}

	log.Printf("starting ssh server on %s", s.Addr)
	log.Fatal(s.ListenAndServe())
}
