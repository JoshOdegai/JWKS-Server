package main

import (
	//"io/ioutil"
	//"crypto/rand"
	//"crypto/rsa"
	//"crypto/x509"
	//"encoding/pem"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	//"fmt"
	//"strings"
	"testing"
	"time"
)

var (
	ErrReadFile  = errors.New("read file error")
	ErrDecodeKey = errors.New("decode key error")

)

func TestGenerateKeys(t *testing.T) {
	var currentKey *rsa.PrivateKey
	var expiredKey *rsa.PrivateKey

	// Call the generateKeys function
	err := generateKeys(&currentKey, &expiredKey)

	// Check for errors in generating keys
	if err != nil {
		t.Fatalf("Error generating keys: %v", err)
	}

	// Check if both currentKey and expiredKey are non-nil
	if currentKey == nil || expiredKey == nil {
		t.Error("generateKeys did not generate both currentKey and expiredKey")
	}

	// Check if currentKey and expiredKey are of type *rsa.PrivateKey
	if currentKey == nil {
		t.Error("currentKey is not of type *rsa.PrivateKey")
	}

	if expiredKey == nil {
		t.Error("expiredKey is not of type *rsa.PrivateKey")
	}
}

func TestGetJWKSHandler(t *testing.T) {
	setup()
	defer teardown()

	req, err := http.NewRequest("GET", "/jwks", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	getJWKSHandler(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the content type
	expectedContentType := "application/json"
	if contentType := rr.Header().Get("Content-Type"); contentType != expectedContentType {
		t.Errorf("Handler returned wrong content type: got %v want %v", contentType, expectedContentType)
	}

	// Decode the response body
	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Errorf("Error decoding response body: %v", err)
	}

	if _, ok := response["keys"]; !ok {
		t.Error("Expected 'keys' field in the response, but not found")
	}
}

func TestIssueTokenHandlerExpiredKey(t *testing.T) {
	// Set up the necessary data for testing
	useExpiredKey := "true"

	// Set the currentKey and expirationTime to values that would trigger the expired key case
	currentKey, _ = generateKeyPair("current-key-id", time.Hour*24)
	expiredKey, _ = generateKeyPair("expired-key-id", time.Hour*24*365*5)
	expirationTime = time.Now().Add(-time.Hour) // Set expiration time in the past

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Call the issueTokenHandler function
		issueTokenHandler(w, r)
	}))

	// Ensure the test server is closed when the test is done
	defer ts.Close()

	// Make a request to the test server with the useExpiredKey query parameter
	resp, err := http.Get(ts.URL + "/issue-token?useExpiredKey=" + useExpiredKey)
	if err != nil {
		t.Fatalf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// Decode the response body
	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		t.Fatalf("Error decoding response body: %v", err)
	}
}

func TestIssueTokenHandlerCurrentKey(t *testing.T) {
	// Set up the necessary data for testing

	// Set the currentKey and expirationTime to values that would trigger the current key case
	currentKey, _ = generateKeyPair("current-key-id", time.Hour*24)
	expiredKey, _ = generateKeyPair("expired-key-id", time.Hour*24*365*5)
	expirationTime = time.Now().Add(time.Hour) // Set expiration time in the future

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Call the issueTokenHandler function
		issueTokenHandler(w, r)
	}))

	// Ensure the test server is closed when the test is done
	defer ts.Close()

	// Make a request to the test server without the useExpiredKey query parameter
	resp, err := http.Get(ts.URL + "/issue-token")
	if err != nil {
		t.Fatalf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// Decode the response body
	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		t.Fatalf("Error decoding response body: %v", err)
	}
}


func TestAuthenticateHandler(t *testing.T) {
	setup()
	defer teardown()

	req, err := http.NewRequest("GET", "/authenticate", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	authenticateHandler(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the content type
	expectedContentType := "application/json"
	if contentType := rr.Header().Get("Content-Type"); contentType != expectedContentType {
		t.Errorf("Handler returned wrong content type: got %v want %v", contentType, expectedContentType)
	}

	// Decode the response body
	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Errorf("Error decoding response body: %v", err)
	}
}





func setup() {
	// Create temporary files or initialize variables for testing
	currentKey, _ = generateKeyPair("current-key-id", time.Hour*24)
	expiredKey, _ = generateKeyPair("expired-key-id", time.Hour*24*365*5)
}

func teardown() {
	// Clean up temporary files or reset variables after testing
	os.Remove("current-private-key-test.pem")
	os.Remove("expired-private-key-test.pem")
}

