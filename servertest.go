package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"errors"
	"os"
	"io/ioutil"
	"strconv"
	"net/http"
	"time"
)

var currentKey *rsa.PrivateKey
var expiredKey *rsa.PrivateKey
var selectedKey *rsa.PrivateKey
var expirationTime time.Time

func main() {
	err := generateKeys(&currentKey, &expiredKey)
	if err != nil {
		fmt.Println("Error generating keys:", err)
		return
	}
	
	// Load private keys from files or other secure storage
	loadKeys()

	http.HandleFunc("/jwks", getJWKSHandler)
	http.HandleFunc("/auth", authenticateHandler)
	http.HandleFunc("/issue-token", issueTokenHandler)

	port := 8080
	fmt.Printf("Server is running at http://localhost:%d\n", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func generateKeys(currentKey, expiredKey **rsa.PrivateKey) error {
	var err error
	*currentKey, err = generateKeyPair("current-key-id", time.Hour*24)
	if err != nil {
		return err
	}
	*expiredKey, err = generateKeyPair("expired-key-id", time.Hour*24*365*5)
	if err != nil {
		return err
	}
	return nil
}

func generateKeyPair(kid string, expiration time.Duration)(*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	
	if expiration != 0 {
        expirationTime = time.Now().Add(expiration)
        saveKeyToFile(fmt.Sprintf("%s-private-key.pem", kid), key, expirationTime)
    } 
	return key, nil
}
	
	
func saveKeyToFile(filename string, key *rsa.PrivateKey, expirationTime time.Time) {
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating private key file:", err)
		return
	}
	defer file.Close()

	err = pem.Encode(file, privateKeyPEM)
	if err != nil {
		fmt.Println("Error encoding private key file:", err)
		return
	}

	fmt.Printf("Private key generated and saved to %s\n", filename)
}


func loadKeys() error {
	// Load both current and expired RSA keys
	currentKeyBytes, err := ioutil.ReadFile("current-key-id-private-key.pem")
	if err != nil {
		return fmt.Errorf("Error reading current private key: %w", err)
	}

	currentKeyBlock, _ := pem.Decode(currentKeyBytes)
	if currentKeyBlock == nil {
		return errors.New("Error decoding current private key block: no valid PEM block found")
	}

	currentKey, err = x509.ParsePKCS1PrivateKey(currentKeyBlock.Bytes)
	if err != nil {
		currentKey = nil
		return fmt.Errorf("Error parsing current private key: %w", err)
	}

	expiredKeyBytes, err := ioutil.ReadFile("expired-key-id-private-key.pem")
	if err != nil {
		return fmt.Errorf("Error reading expired private key: %w", err)
	}

	expiredKeyBlock, _ := pem.Decode(expiredKeyBytes)
	if expiredKeyBlock == nil {
		return errors.New("Error decoding expired private key block: no valid PEM block found")
	}

	expiredKey, err = x509.ParsePKCS1PrivateKey(expiredKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("Error parsing expired private key: %w", err)
	}

	return nil
}


func getJWKSHandler(w http.ResponseWriter, r *http.Request) {
	// Return JWKS only with non-expired keys
	keys := []map[string]interface{}{}
	var newExpirationTime time.Time
	if time.Now().After(expirationTime) {
		expiredKey = currentKey
		newCurrentKey, _ := generateKeyPair("current-key-id", time.Hour*24)
		currentKey = newCurrentKey
		newExpirationTime = time.Now().Add(time.Hour*24)
		expirationTime = newExpirationTime

		keys = append(keys, getJWK(currentKey, "current-key-id-private-key"))
	} else {
			keys = append(keys, getJWK(currentKey, "current-key-id-private-key"))
	}

	jwks := map[string]interface{}{"keys": keys}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func getJWK(key *rsa.PrivateKey, kid string) map[string]interface{} {
	pubKey := key.PublicKey
	return map[string]interface{}{
		"kid": kid,
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&pubKey)),
	}
}


func issueTokenHandler(w http.ResponseWriter, r *http.Request) {

	// Use expired key if specified in the query parameter
	userID := 123
	useExpiredKey := r.URL.Query().Get("useExpiredKey")
	
	if time.Now().After(expirationTime) || useExpiredKey == "true" {
		token := generateTokenWithExpiration(userID, expiredKey, expirationTime)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"token": token})
		return
	} else {
		selectedKey = currentKey
	}

	token := generateToken(userID, selectedKey)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"token": token})
}

func authenticateHandler(w http.ResponseWriter, r *http.Request) {
		userID := 123
		token := generateToken(userID, currentKey)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"token": token})
}

func generateToken(userID int, key *rsa.PrivateKey) string {
	claims := map[string]interface{}{
		"sub": strconv.Itoa(userID),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	
	var kid string
	if selectedKey == expiredKey {
		kid = "expired-key-id"
	} else {
		kid = "current-key-id"
	}

	header := map[string]interface{}{
		"alg": "RS256",
		"kid": kid,
	}

	// Create JWT
	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsBytes)

	signatureInput := fmt.Sprintf("%s.%s", headerEncoded, claimsEncoded)

	hashed := sha256.Sum256([]byte(signatureInput))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])

	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	token := fmt.Sprintf("%s.%s.%s", headerEncoded, claimsEncoded, signatureEncoded)
	return token
}

func generateTokenWithExpiration(userID int, key *rsa.PrivateKey, expirationTime time.Time) string {
	claims := map[string]interface{}{
		"sub": strconv.Itoa(userID),
		"exp": expirationTime.Unix(), 
	}

	var kid string
	if key == expiredKey {
		kid = "expired-key-id"
	} else {
		kid = "current-key-id"
	}

	header := map[string]interface{}{
		"alg": "RS256",
		"kid": kid,
	}

	// Create JWT
	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsBytes)

	signatureInput := fmt.Sprintf("%s.%s", headerEncoded, claimsEncoded)

	hashed := sha256.Sum256([]byte(signatureInput))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])

	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	token := fmt.Sprintf("%s.%s.%s", headerEncoded, claimsEncoded, signatureEncoded)
	return token
}
