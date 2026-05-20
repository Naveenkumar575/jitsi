/*
|--------------------------------------------------------------------------
| FILE : main.go
| DESC : Jitsi JWT Token Server (Go + CORS Enabled)
|--------------------------------------------------------------------------
*/

package main

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	appID      = "vpaas-magic-cookie-f6af969cc08141a29d1483448c6af720"
	keyID      = "vpaas-magic-cookie-f6af969cc08141a29d1483448c6af720/02137d"
	privateKey *rsa.PrivateKey

	/// 🔹 Track first user as moderator
	roomState = make(map[string]bool)
	mu        sync.Mutex
)

func main() {

	/// 🔹 Load private key
	keyData, err := os.ReadFile("private.pem")
	if err != nil {
		log.Fatal("❌ Cannot read private.pem")
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		log.Fatal("❌ Invalid private key")
	}

	/// 🔹 Routes
	http.HandleFunc("/token", generateToken)

	fmt.Println("🚀 Server running at http://localhost:8080")

	log.Fatal(http.ListenAndServe(":8080", nil))
}

/*
|--------------------------------------------------------------------------
| FUNCTION : generateToken
| PURPOSE  : Generate JWT for Jitsi (8x8)
|--------------------------------------------------------------------------
*/
func generateToken(w http.ResponseWriter, r *http.Request) {

	/// 🔥 CORS HEADERS (VERY IMPORTANT FOR WEB)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	/// 🔥 Handle preflight request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	/// 🔹 Get query params
	room := r.URL.Query().Get("room")
	name := r.URL.Query().Get("name")

	if room == "" {
		http.Error(w, "room parameter required", http.StatusBadRequest)
		return
	}

	if name == "" {
		name = "Guest"
	}

	/// 🔹 Assign moderator to first user
	mu.Lock()
	isModerator := false

	if !roomState[room] {
		isModerator = true
		roomState[room] = true
	}

	mu.Unlock()

	/// 🔹 JWT Claims
	claims := jwt.MapClaims{
		"aud": "jitsi",
		"iss": "chat",
		"sub": appID,
		"room": room,
		"exp": time.Now().Add(time.Hour).Unix(),
		"context": map[string]interface{}{
			"user": map[string]interface{}{
				"name":      name,
				"moderator": isModerator,
			},
		},
	}

	/// 🔹 Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	/// 🔹 Sign token
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "Token signing failed", http.StatusInternalServerError)
		return
	}

	/// 🔹 Return JWT
	w.Write([]byte(signedToken))
}