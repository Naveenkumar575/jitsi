package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	appID      = "vpaas-magic-cookie-8d7b7511de354ef6b70a568a17618d3c"
	keyID      = "vpaas-magic-cookie-8d7b7511de354ef6b70a568a17618d3c/914289"
	privateKey *rsa.PrivateKey
	roomState  = make(map[string]bool)
	mu         sync.Mutex
)

func main() {
	keyData, err := os.ReadFile("private.pem")
	if err != nil {
		log.Fatal("❌ Cannot read private.pem")
	}
	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		log.Fatal("❌ Invalid private key")
	}

	http.HandleFunc("/token",         generateToken)
	http.HandleFunc("/health",        healthCheck)
	http.HandleFunc("/webhooks/jaas", handleJaasWebhook)

	fmt.Println("🚀 Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ─────────────────────────────────────────────
// GOOGLE AUTH TOKEN (from service account)
// ─────────────────────────────────────────────
func getGoogleAccessToken() (string, error) {
	clientEmail := os.Getenv("GOOGLE_CLIENT_EMAIL")
	privateKeyPEM := os.Getenv("GOOGLE_PRIVATE_KEY")

	// Replace literal \n with real newlines (Render env vars need this)
	privateKeyPEM = strings.ReplaceAll(privateKeyPEM, `\n`, "\n")

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("not an RSA key")
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   clientEmail,
		"sub":   clientEmail,
		"aud":   "https://oauth2.googleapis.com/token",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"scope": "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/devstorage.read_write",
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(rsaKey)
	if err != nil {
		return "", err
	}

	// Exchange signed JWT for access token
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signed},
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	token, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("no access_token in response: %v", result)
	}
	return token, nil
}

// ─────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────
func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// ─────────────────────────────────────────────
// WEBHOOK HANDLER
// ─────────────────────────────────────────────
func handleJaasWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	eventType, _ := payload["eventType"].(string)
	log.Printf("📩 Webhook received: %s", eventType)

	if eventType != "RECORDING_UPLOADED" {
		w.WriteHeader(http.StatusOK)
		return
	}

	data, _     := payload["data"].(map[string]interface{})
	fqn, _      := payload["fqn"].(string)
	tsFloat, _  := payload["timestamp"].(float64)
	timestamp   := int64(tsFloat)

	preAuthLink, _ := data["preAuthenticatedLink"].(string)
	sessionId, _   := data["sessionId"].(string)
	durationMs, _  := data["durationMs"].(float64)

	// Extract meetingId from fqn = "vpaas-magic-cookie-xxx/MEETING_ID"
	meetingId := ""
	if idx := strings.Index(fqn, "/"); idx >= 0 {
		meetingId = fqn[idx+1:]
	}

	if preAuthLink == "" || meetingId == "" {
		log.Println("❌ Missing preAuthLink or meetingId")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Return 200 immediately — 8x8 has a short timeout
	w.WriteHeader(http.StatusOK)

	go func() {
		projectId := os.Getenv("FIREBASE_PROJECT_ID")
		if projectId == "" {
			log.Println("❌ FIREBASE_PROJECT_ID not set")
			return
		}

		// Get Google access token
		accessToken, err := getGoogleAccessToken()
		if err != nil {
			log.Printf("❌ Failed to get Google token: %v", err)
			return
		}

		client := &http.Client{Timeout: 120 * time.Second}

		// ── 1. Download the mp4 from 8x8 ──────────────────────
		log.Printf("⬇️  Downloading recording for meeting %s", meetingId)
		dlResp, err := client.Get(preAuthLink)
		if err != nil {
			log.Printf("❌ Download failed: %v", err)
			return
		}
		defer dlResp.Body.Close()
		videoBytes, err := io.ReadAll(dlResp.Body)
		if err != nil {
			log.Printf("❌ Read failed: %v", err)
			return
		}
		log.Printf("✅ Downloaded %d bytes", len(videoBytes))

		// ── 2. Upload to Firebase Storage ──────────────────────
		bucketName  := projectId + ".appspot.com"
		storagePath := fmt.Sprintf("recordings/%s/%s.mp4", meetingId, sessionId)
		encodedPath := url.PathEscape(storagePath)
		uploadURL   := fmt.Sprintf(
			"https://storage.googleapis.com/upload/storage/v1/b/%s/o?uploadType=media&name=%s&predefinedAcl=publicRead",
			bucketName, encodedPath,
		)

		uploadReq, _ := http.NewRequest("POST", uploadURL, bytes.NewReader(videoBytes))
		uploadReq.Header.Set("Content-Type", "video/mp4")
		uploadReq.Header.Set("Authorization", "Bearer "+accessToken)

		uploadResp, err := client.Do(uploadReq)
		if err != nil {
			log.Printf("❌ Storage upload failed: %v", err)
			return
		}
		uploadResp.Body.Close()

		publicUrl := fmt.Sprintf(
			"https://storage.googleapis.com/%s/%s",
			bucketName, storagePath,
		)
		log.Printf("✅ Uploaded to: %s", publicUrl)

		// ── 3. Fetch meeting title + category from Firestore ───
		firestoreBase := fmt.Sprintf(
			"https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents",
			projectId,
		)

		meetingTitle := ""
		category     := ""

		meetingReq, _ := http.NewRequest("GET",
			fmt.Sprintf("%s/meetings/%s", firestoreBase, meetingId), nil)
		meetingReq.Header.Set("Authorization", "Bearer "+accessToken)
		meetingResp, err := client.Do(meetingReq)
		if err == nil && meetingResp.StatusCode == 200 {
			var meetingDoc map[string]interface{}
			json.NewDecoder(meetingResp.Body).Decode(&meetingDoc)
			meetingResp.Body.Close()
			if fields, ok := meetingDoc["fields"].(map[string]interface{}); ok {
				meetingTitle = firestoreGetString(fields, "title")
				category     = firestoreGetString(fields, "category")
			}
		}

		// ── 4. Fetch participant UIDs ───────────────────────────
		participantUids := []interface{}{}

		partReq, _ := http.NewRequest("GET",
			fmt.Sprintf("%s/meetings/%s/participants", firestoreBase, meetingId), nil)
		partReq.Header.Set("Authorization", "Bearer "+accessToken)
		partResp, err := client.Do(partReq)
		if err == nil && partResp.StatusCode == 200 {
			var partDoc map[string]interface{}
			json.NewDecoder(partResp.Body).Decode(&partDoc)
			partResp.Body.Close()
			if docs, ok := partDoc["documents"].([]interface{}); ok {
				for _, d := range docs {
					if docMap, ok := d.(map[string]interface{}); ok {
						if name, ok := docMap["name"].(string); ok {
							parts := strings.Split(name, "/")
							uid := parts[len(parts)-1]
							participantUids = append(participantUids,
								map[string]interface{}{"stringValue": uid})
						}
					}
				}
			}
		}

		// ── 5. Write recording doc to Firestore ────────────────
		recordedAt := time.Unix(0, timestamp*int64(time.Millisecond)).UTC().Format(time.RFC3339)

		firestoreDoc := map[string]interface{}{
			"fields": map[string]interface{}{
				"meetingId":    firestoreStr(meetingId),
				"meetingTitle": firestoreStr(meetingTitle),
				"sessionId":    firestoreStr(sessionId),
				"url":          firestoreStr(publicUrl),
				"recordedAt":   map[string]string{"timestampValue": recordedAt},
				"createdAt":    map[string]string{"timestampValue": time.Now().UTC().Format(time.RFC3339)},
				"durationMs":   map[string]interface{}{"integerValue": fmt.Sprintf("%d", int64(durationMs))},
				"participantUids": map[string]interface{}{
					"arrayValue": map[string]interface{}{"values": participantUids},
				},
				"participantCount": map[string]interface{}{
					"integerValue": fmt.Sprintf("%d", len(participantUids)),
				},
				"category": firestoreStr(category),
			},
		}

		docBody, _ := json.Marshal(firestoreDoc)
		writeReq, _ := http.NewRequest("POST",
			fmt.Sprintf("%s/meetings/%s/recordings", firestoreBase, meetingId),
			bytes.NewReader(docBody),
		)
		writeReq.Header.Set("Content-Type", "application/json")
		writeReq.Header.Set("Authorization", "Bearer "+accessToken)

		writeResp, err := client.Do(writeReq)
		if err != nil {
			log.Printf("❌ Firestore write failed: %v", err)
			return
		}
		defer writeResp.Body.Close()
		log.Printf("✅ Recording doc saved (status %d) for meeting %s",
			writeResp.StatusCode, meetingId)
	}()
}

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
func firestoreStr(s string) map[string]string {
	return map[string]string{"stringValue": s}
}

func firestoreGetString(fields map[string]interface{}, key string) string {
	if f, ok := fields[key].(map[string]interface{}); ok {
		if v, ok := f["stringValue"].(string); ok {
			return v
		}
	}
	return ""
}

// ─────────────────────────────────────────────
// TOKEN GENERATOR (unchanged)
// ─────────────────────────────────────────────
func generateToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	room := r.URL.Query().Get("room")
	name := r.URL.Query().Get("name")
	if room == "" {
		http.Error(w, "room parameter required", http.StatusBadRequest)
		return
	}
	if name == "" {
		name = "Guest"
	}

	mu.Lock()
	isModerator := false
	if !roomState[room] {
		isModerator = true
		roomState[room] = true
	}
	mu.Unlock()

	claims := jwt.MapClaims{
		"aud":  "jitsi",
		"iss":  "chat",
		"sub":  appID,
		"room": room,
		"exp":  time.Now().Add(time.Hour).Unix(),
		"context": map[string]interface{}{
			"user": map[string]interface{}{
				"name":      name,
				"moderator": isModerator,
			},
			"features": map[string]interface{}{
				"recording":     isModerator,
				"livestreaming": false,
				"outbound-call": false,
				"transcription": false,
			},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "Token signing failed", http.StatusInternalServerError)
		return
	}
	w.Write([]byte(signedToken))
}
