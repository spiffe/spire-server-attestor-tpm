package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

// FIXME share this somehow
type SPIFFETrustBundleClaims struct {
	SPIFFETrustBundle string `json:"spiffetb"`
	jwt.RegisteredClaims
}
type SPIFFENestedTrustBundleClaims struct {
	SPIFFENestedTrustBundle string `json:"jwt"`
	jwt.RegisteredClaims
}

type KeysetConfig struct {
	URL    string   `yaml:"url"`
	Backup string   `yaml:"backup,omitempty"`
	Chain  []string `yaml:"chain"`
}

type Config struct {
	Socket string                  `yaml:"socket,omitempty"`
	KeyDir string                  `yaml:"keydir,omitempty"`
	Keyset map[string]KeysetConfig `yaml:"keyset"`
}

var config Config
var allKeys map[string]*rsa.PublicKey

func fetchToken(ctx context.Context, URL string) (token string, err error) {
	u, err := url.Parse(URL)
	if err != nil {
		return "", err
	}

	if u.Scheme == "" || u.Scheme == "file" {
		token, err := os.ReadFile(u.Path)
		if err != nil {
			return "", err
		}
		return string(token), nil
	}

	if u.Scheme == "http" || u.Scheme == "https" {
		c := http.Client{}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
		if err != nil {
			return "", err
		}

		resp, err := c.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return string(body), nil
	}
	return "", errors.New("Something went wrong")
}

func verifyTokenReturnTrustBundle(allKeys map[string]*rsa.PublicKey, ksc KeysetConfig, token string) (trustbundle string, err error) {
	var ptoken *jwt.Token
	backupAvailable := (ksc.Backup != "")
	l := len(ksc.Chain)
	if l > 1 {
		toProcess := ksc.Chain[0 : l-1]
		for _, key := range toProcess {
			ptoken, err = jwt.ParseWithClaims(token, &SPIFFENestedTrustBundleClaims{}, func(token *jwt.Token) (interface{}, error) {
				return allKeys[key], nil
			}, jwt.WithLeeway(5*time.Second))
			if err != nil {
				if err.Error() == "token signature is invalid: crypto/rsa: verification error" && backupAvailable {
					ptoken, err = jwt.ParseWithClaims(token, &SPIFFENestedTrustBundleClaims{}, func(token *jwt.Token) (interface{}, error) {
						return allKeys[ksc.Backup], nil
					}, jwt.WithLeeway(5*time.Second))
					if err == nil {
						fmt.Printf("Backup key used!\n")
						backupAvailable = false
					} else if err.Error() != "token signature is invalid: crypto/rsa: verification error" {
						fmt.Printf("Backup key used!\n")
						return "", err
					}
				} else {
					return "", err
				}
			}
			claims, ok := ptoken.Claims.(*SPIFFENestedTrustBundleClaims)
			if !ok {
				return "", errors.New("Failed to parse claims")
			}
			token = claims.SPIFFENestedTrustBundle
		}
	}
	last := ksc.Chain[l-1]
	ptoken, err = jwt.ParseWithClaims(token, &SPIFFETrustBundleClaims{}, func(token *jwt.Token) (interface{}, error) {
		return allKeys[last], nil
	}, jwt.WithLeeway(5*time.Second))
	if err != nil {
		if err.Error() == "token signature is invalid: crypto/rsa: verification error" && backupAvailable {
			ptoken, err = jwt.ParseWithClaims(token, &SPIFFENestedTrustBundleClaims{}, func(token *jwt.Token) (interface{}, error) {
				return allKeys[ksc.Backup], nil
			}, jwt.WithLeeway(5*time.Second))
			if err == nil {
				fmt.Printf("Backup key used!\n")
				backupAvailable = false
			} else if err.Error() != "token signature is invalid: crypto/rsa: verification error" {
				fmt.Printf("Backup key used!\n")
				return "", err
			}
		} else {
			return "", err
		}
	}
	claims, ok := ptoken.Claims.(*SPIFFETrustBundleClaims)
	if !ok {
		return "", errors.New("Failed to parse claims")
	}
	return claims.SPIFFETrustBundle, nil
}

func trustBundleHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	params := r.URL.Query()
	instance := params.Get("instance")
	if instance == "" {
		http.Error(w, "Required param instance missing", http.StatusBadRequest)
		return
	}

	URL := config.Keyset[instance].URL
	token, err := fetchToken(ctx, URL)
	if err != nil {
		fmt.Printf("Failed to get token %v\n", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	trustbundle, err := verifyTokenReturnTrustBundle(allKeys, config.Keyset[instance], token)
	if err != nil {
		fmt.Printf("Failed to get token %v\n", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(trustbundle))
}

func main() {
	allKeys = make(map[string]*rsa.PublicKey)
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage:", os.Args[0], "configfile keyset|-l <url override>")
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
	if config.KeyDir == "" {
		config.KeyDir = "keys"
	}
	keyDir := filepath.Join(filepath.Dir(os.Args[1]), config.KeyDir)
	files, err := os.ReadDir(keyDir)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	for _, file := range files {
		var key *rsa.PublicKey
		keyData, err := os.ReadFile(filepath.Join(keyDir, file.Name()))
		if err != nil {
			fmt.Println("could not read PEM file: %v", err)
			return
		}
		key, err = jwt.ParseRSAPublicKeyFromPEM(keyData)
		if err != nil {
			fmt.Printf("could not read PEM file: %s %v\n", file.Name(), err)
			return
		}
		allKeys[file.Name()] = key
	}

	for _, value := range config.Keyset {
		if value.URL == "" {
			fmt.Printf("URL must be set\n")
			return
		}

		u, err := url.Parse(value.URL)
		if err != nil {
			fmt.Println("Error parsing url %v", err)
			return
		}
		if u.Scheme != "" && u.Scheme != "file" && u.Scheme != "http" && u.Scheme != "https" {
			fmt.Println("Unsupported url scheme %s", u.Scheme)
			return
		}

		if value.Backup != "" {
			if _, ok := allKeys[value.Backup]; !ok {
				fmt.Printf("Key specified but doesnt exist %s\n", value.Backup)
				return
			}
		}
		if len(value.Chain) == 0 {
			fmt.Printf("Chain needs at least one key\n")
			return
		}

		slices.Reverse(value.Chain)

		for _, file := range value.Chain {
			if _, ok := allKeys[file]; !ok {
				fmt.Printf("Key specified but doesnt exist %s\n", file)
				return
			}
		}
	}

	fmt.Println("Config loaded successfully")
	ctx := context.Background()
	if os.Args[2] == "-l" {
		if config.Socket == "" {
			fmt.Printf("You must specify a socket in listen mode\n")
		}
		fmt.Printf("Listen Mode\n")
		mux := http.NewServeMux()
		mux.HandleFunc("/trustbundle", trustBundleHandler)

		s := http.Server{
			Handler: mux,
		}

		ul, err := net.Listen("unix", config.Socket)
		if err != nil {
			fmt.Printf("Error %v\n", err)
			return
		}
		s.Serve(ul)
	} else {
		if _, ok := config.Keyset[os.Args[2]]; !ok {
			fmt.Printf("Keyset specified but not found in the config %s\n", os.Args[2])
			return
		}
		URL := config.Keyset[os.Args[2]].URL
		if len(os.Args) >= 4 {
			URL = os.Args[3]
		}
		token, err := fetchToken(ctx, URL)
		if err != nil {
			fmt.Printf("Failed to get token %v\n", err)
			return
		}
		trustbundle, err := verifyTokenReturnTrustBundle(allKeys, config.Keyset[os.Args[2]], token)
		if err != nil {
			fmt.Printf("Failed to get token %v\n", err)
			return
		}
		fmt.Printf("Got trustbundle:\n%s", trustbundle)
	}
}
