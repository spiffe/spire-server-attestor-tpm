package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"path/filepath"

	"gopkg.in/yaml.v3"
	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	ListenAddr string `yaml:"listen-addr"`
	Socket string `yaml:"socket"`
	KeyDir string `yaml:"keydir,omitempty"`
	Backup string `yaml:"backup,omitempty"`
	Primary string `yaml:"primary"`
	AllowedAddrs []string `yaml:"allowed-addrs"`
}

var config Config
var primarykey *rsa.PublicKey
var backupkey *rsa.PublicKey
var allowedhosts map[string]struct{}
var socket string

type SPIFFETrustBundleOrNestedClaims struct {
	SPIFFETrustBundle string `json:"spiffetb,omitempty"`
	SPIFFENestedTrustBundle string `json:"jwt,omitempty"`
	jwt.RegisteredClaims
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	index := strings.LastIndex(r.RemoteAddr, `:`)
	if index == -1 {
		fmt.Printf("Couldn't find port in RemoteAddr. This shouldn't ever happen %s\n", r.RemoteAddr)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	remotehost := r.RemoteAddr[:index]
	if _, ok := allowedhosts[remotehost]; !ok {
		fmt.Printf("Blocking request from %s\n", remotehost)
		http.Error(w, fmt.Sprintf("You are not allowed %s", remotehost), http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(body) < 1 {
		http.Error(w, "Not enough bytes", http.StatusBadRequest)
		return
	}

	_, err = jwt.ParseWithClaims(string(body), &SPIFFETrustBundleOrNestedClaims{}, func(token *jwt.Token) (interface{}, error) {
		return primarykey, nil
	}, jwt.WithLeeway(5 * time.Second))
	if err != nil {
		ok := false
		if err.Error() == "token signature is invalid: crypto/rsa: verification error" && backupkey != nil {
			_, err = jwt.ParseWithClaims(string(body), &SPIFFETrustBundleOrNestedClaims{}, func(token *jwt.Token) (interface{}, error) {
				return backupkey, nil
			}, jwt.WithLeeway(5 * time.Second))
			if err == nil {
				fmt.Printf("Backup key used!\n")
				ok = true
			} else if err.Error() != "token signature is invalid: crypto/rsa: verification error" {
				fmt.Printf("Backup key used!\n")
			}
		}
		if !ok {
			fmt.Printf("Failed to parse request %v\n", err)
			http.Error(w, "Failed to parse your token", http.StatusBadRequest)
			return
		}
	}

	c := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socket)
			},
		},
	}


	ureq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/sign", bytes.NewBuffer(body))
	if err != nil {
		fmt.Println("Error creating request:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	ureq.Header.Set("Content-Type", "application/jwt")

	uresp, err := c.Do(ureq)
	if err != nil {
		fmt.Println("Error talking to socket:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
        sbody, err := io.ReadAll(uresp.Body)
        if err != nil {
		fmt.Println("Error talking to socket:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
                return
        }
	defer uresp.Body.Close()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sbody))
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
        configData = os.ExpandEnv(configData)
	err = yaml.Unmarshal([]byte(configData), &config)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	if config.KeyDir == "" {
		config.KeyDir = "keys"
	}
	keyDir := filepath.Join(filepath.Dir(os.Args[1]), config.KeyDir)

	socket = config.Socket

	allowedhosts = make(map[string]struct{})
	for _, i := range config.AllowedAddrs {
		allowedhosts[i] = struct{}{}
	}

	publickey, err := os.ReadFile(filepath.Join(keyDir, config.Primary))
	if err != nil {
		fmt.Println("could not read Primary PEM file: %v", err)
		return
	}
	primarykey, err = jwt.ParseRSAPublicKeyFromPEM(publickey)
	if err != nil {
		fmt.Println("could not read Primary PEM file: %v", err)
		return
	}
	if config.Backup != "" {
		publickey, err = os.ReadFile(filepath.Join(keyDir, config.Backup))
		if err != nil {
			fmt.Println("could not read Backup PEM file: %v", err)
			return
		}
		backupkey, err = jwt.ParseRSAPublicKeyFromPEM(publickey)
		if err != nil {
			fmt.Println("could not read Primary PEM file: %v", err)
			return
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sign", signHandler)

	err = http.ListenAndServe(config.ListenAddr, mux)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		return
	}
}
