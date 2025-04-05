package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
	"gopkg.in/yaml.v3"
)

var config Config
var tpmconfig *tpmjwt.TPMConfig
var issuer string
var duration time.Duration

// FIXME share this somehow
type SPIFFETrustBundleClaims struct {
	SPIFFETrustBundle string `json:"spiffetb"`
	jwt.RegisteredClaims
}
type SPIFFENestedTrustBundleClaims struct {
	SPIFFENestedTrustBundle string `json:"jwt"`
	jwt.RegisteredClaims
}

type Config struct {
	Socket   string `yaml:"socket"`
	TPMAddr  string `yaml:"tpm-address"`
	Duration string `yaml:"duration"`
	Dir      string `hcl:"dir"`
	Filename string `hcl:"filename,omitempty"`
	TMPFile  string `hcl:"tmpfile,omitempty"`
	Issuer   string `yaml:"issuer,omitempty`
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	contentType := r.Header.Get("Content-Type")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	keyctx, err := tpmjwt.NewTPMContext(ctx, tpmconfig)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	tpmjwt.SigningMethodTPMRS256.Override()
	var token *jwt.Token

	if contentType == "application/jwt" {
		claims := SPIFFENestedTrustBundleClaims{
			string(body),
			jwt.RegisteredClaims{
				ExpiresAt: &jwt.NumericDate{time.Now().Add(duration)},
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				Issuer:    issuer,
			},
		}
		token = jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)
	} else {
		claims := SPIFFETrustBundleClaims{
			string(body),
			jwt.RegisteredClaims{
				ExpiresAt: &jwt.NumericDate{time.Now().Add(duration)},
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
				Issuer:    issuer,
			},
		}
		token = jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)
	}
	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenString))
}

func publishHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = os.WriteFile(filepath.Join(config.Dir, config.TMPFile), []byte(body), 0644)
	if err != nil {
		fmt.Printf("Error writing bundle: %v\n", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	err = os.Chmod(filepath.Join(config.Dir, config.TMPFile), 0644)
	if err != nil {
		fmt.Printf("Error chowning bundle: %v\n", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	err = os.Rename(filepath.Join(config.Dir, config.TMPFile), filepath.Join(config.Dir, config.Filename))
	if err != nil {
		fmt.Printf("Error renaming bundle: %v\n", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage:", os.Args[0], "/path/to/config.conf")
		return
	}
	configData, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("Error reading config file", err)
		return
	}
	configData = []byte(os.ExpandEnv(string(configData)))
	err = yaml.Unmarshal([]byte(configData), &config)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	if config.Issuer == "" {
		issuer, err = os.Hostname()
		if err != nil {
			fmt.Printf("Error %v\n", err)
			return
		}
	} else {
		issuer = config.Issuer
	}
	if !strings.HasPrefix(config.TPMAddr, "0x") {
		fmt.Printf("Error tpm-persistent-handle must start with 0x")
		return
	}
	handle, err := strconv.ParseInt(config.TPMAddr[2:], 16, 64)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		return
	}

	if config.Dir == "" {
		fmt.Printf("Error: you must configure dir in which to write the token")
		return
	}
	if config.Filename == "" {
		config.Filename = "spiffetrustbundle.token"
	}
	if config.TMPFile == "" {
		config.TMPFile = "spiffetrustbundle.token.tmp"
	}

	duration, err = time.ParseDuration(config.Duration)

	rwc, err := tpmutil.OpenTPM("/dev/tpmrm0")
	defer rwc.Close()
	rwr := transport.FromReadWriter(rwc)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		return
	}

	// get an existing tpm based keys persistent or handle
	// pass that to this library along with any session authorization
	rpub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(handle),
	}.Execute(rwr)

	if err != nil {
		fmt.Printf("Error %v\n", err)
		return
	}

	tpmconfig = &tpmjwt.TPMConfig{
		TPMDevice: rwc,
		NamedHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(handle),
			Name:   rpub.Name,
		},
	}

	fmt.Println("Starting Server")

	mux := http.NewServeMux()
	mux.HandleFunc("/sign", signHandler)
	mux.HandleFunc("/publish", publishHandler)

	s := http.Server{
		Handler: mux,
	}

	ul, err := net.Listen("unix", config.Socket)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		return
	}
	s.Serve(ul)
}
