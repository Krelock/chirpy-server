package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Krelock/chirpy-server/internal/auth"
	"github.com/Krelock/chirpy-server/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries // My database
	platform       string
	jwSecret       string
	PolkaKey       string
}
type User struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"-" db:"hashed_password"`
	IsChirpyRed    bool      `json:"is_chirpy_red"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1) // Increment the counter safely
		next.ServeHTTP(w, r)      // Pass the request to the next handler
	})
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err := cfg.DB.DeleteAllUsers(r.Context())
	if err != nil {
		log.Printf("Error deleting users: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)

	// Use Store() to set the counter back to 0
	// Send an appropriate response
}

/*
The parameters:

	w http.ResponseWriter: This is your "output"—what you send back to the client (e.g., text, headers).
	_ *http.Request: This is your "input"—the client's HTTP request (e.g., URL, headers, etc.).
*/
func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	hits := cfg.fileserverHits.Load() // Safely load the current hit count
	w.Header().Set("Content-Type", "text/html")
	htmlResponse := fmt.Sprintf(`<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>`, hits)
	w.Write([]byte(htmlResponse))
	w.WriteHeader(http.StatusOK) // Set 200 OK status
	// Write the response body

}

func removeProfane(text string) string {
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}

	words := strings.Split(text, " ")

	for i := 0; len(words) > i; i++ {
		lowerWord := strings.ToLower(words[i])
		for _, profaneWord := range profaneWords {
			if lowerWord == profaneWord {
				words[i] = "****"
				break
			}
		}
	}
	return strings.Join(words, " ")
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	
	
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error creating token: %s", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

    userID, err := auth.ValidateJWT(token, cfg.jwSecret)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return

	}
	
	
	
	//cfg *apiConfig         | How we access the data base aka DB *database.Queries
	// w http.ResponseWriter | Sends data back can be accessed with w
	// r *http.Request       | Recives data can be accessed with r

	// Parameters for incoming data
	type parameters struct {
		Body   string `json:"body"`
	}
	
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {

		log.Printf("Error decoding parameters: %s", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// 2. Validate
	if len(params.Body) > 140 {
		log.Printf("Error too long: %s", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// 3. Clean the body
	cleanedBody := removeProfane(params.Body)

	// 4. Parse and validate user ID
	



	// Parameters for outgoing data
	type chirpResponse struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserId    string    `json:"user_id"`
	}

	// First define the params
	chirp, err := cfg.DB.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleanedBody, // your cleaned chirp text
		UserID: uuid.NullUUID{UUID: userID, Valid: true},
	})
	if err != nil {
		log.Printf("Error creating chirp: %s", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// This creates the response using our chirpResponse struct
	response := chirpResponse{
		ID:        chirp.ID.String(),
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserId:    chirp.UserID.UUID.String(),
	}

	// This converts our struct to JSON
	data, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshaling: %s", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return

	}
	// These lines send it back to the client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated) // 201
	w.Write(data)

}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	hashed_password, err := auth.HashPassword(params.Password)
	if err != nil {
		http.Error(w, "Could not hash password", http.StatusInternalServerError)
		return
	}
	dbUser, err := cfg.DB.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashed_password,
	})
	if err != nil {
		// handle the error appropriately
		log.Printf("Error creating user: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return

	}

	user := User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	}

	dat, err := json.Marshal(user)
	if err != nil {
		log.Printf("Error marshalling user: %s", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(dat)
}

func (cfg *apiConfig) passwordVerify(w http.ResponseWriter, r *http.Request) {
	log.Println("Received login request")
	ctx := r.Context()
	type LoginResponse struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
		Token     string    `json:"token"`
		RefreshToken string `json:"refresh_token"`
		IsChirpyRed  bool      `json:"is_chirpy_red"` 
	}

	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
		Expires  *int   `json:"expires_in_seconds"`
	}
	
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)

	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return

	}
	
	if params.Email == "" || params.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}
	
	//expires parameter typically represents how long (in seconds) a token should remain valid before it expires.
	/* The key points about tokens are:

    They prove who you are after logging in
    They save you from having to log in for every single request
    They can contain information about what you're allowed to do
	*/
	/*if params.Expires != nil {
		if *params.Expires <= 0 {
			defaultExpire = 3600 // use default for negative or zero values
		} else if *params.Expires > 3600 {
			defaultExpire = 3600
		} else {
			defaultExpire = *params.Expires
		}
	}
	*/
	

	user, err := cfg.DB.GetUsers(ctx, params.Email)
	if err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}
	err = auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}
	
	jwtToken, err := auth.MakeJWT(user.ID, cfg.jwSecret, time.Hour)
	
	if err != nil {
		http.Error(w, "Error creating jwtToken", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		http.Error(w, "Error creating refresh token", http.StatusInternalServerError)
		return
	}
	Reparams := database.InsertRefreshParams{
		Token:  refreshToken,
		UserID: uuid.NullUUID{UUID: user.ID, Valid: true},
	}
	// insert refreshtoken into database
	err = cfg.DB.InsertRefresh(ctx, Reparams)
	if err != nil {
		http.Error(w, "Error ineserting refresh token", http.StatusInternalServerError)
	}


	response := LoginResponse{
		ID:        user.ID.String(),
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
		Token:     jwtToken,
		RefreshToken: refreshToken,
		IsChirpyRed:  user.IsChirpyRed,

	}

	encoder := json.NewEncoder(w)
	err = encoder.Encode(response)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

}

// getAllChirps handles the GET /api/chirps endpoint
// It retrieves all chirps from the database and returns them as JSON
func (cfg *apiConfig) getAllChirps(w http.ResponseWriter, r *http.Request) {
	// Initialize an empty slice to store our response chirps
	
	

	chirps := []Chirp{}
	authorIDString := r.URL.Query().Get("author_id")
	sortOrder := r.URL.Query().Get("sort")
	
 
    var authorID uuid.NullUUID
    if authorIDString != "" {
        // Only try to parse if the string isn't empty
        parsed, err := uuid.Parse(authorIDString)
        if err != nil {
            http.Error(w, "Invalid author_id", http.StatusBadRequest)
            return
        }
        authorID = uuid.NullUUID{
            UUID: parsed,
            Valid: true,
        }
    }
    
	// Query the database for all chirps using the request's context
	list_of_chirps, err := cfg.DB.GetChirps(r.Context(), authorID)
	if err != nil {
		// Log the error for debugging purposes
		log.Printf("Error receiving chirps: %s", err)
		// Send an error response to the client
		http.Error(w, "Failed to retrieve chirps", http.StatusInternalServerError)
		return
	}

	// Transform each database chirp into our response format
	for _, chirp := range list_of_chirps {
		// Create a new response chirp with proper JSON field names
		responseChirp := Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID.UUID, // Extract UUID from NullUUID
		}
		// Add the transformed chirp to our response slice
		chirps = append(chirps, responseChirp)
	}

	
	
	if sortOrder == "desc" {
		sort.Slice(chirps, func(i,j int) bool {
			return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
		})
	}else {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
		})

	}
	


	// Set response header to indicate JSON content
	w.Header().Set("Content-Type", "application/json")
	// Set successful status code
	w.WriteHeader(http.StatusOK)
	// Encode and write the JSON response
	if err := json.NewEncoder(w).Encode(chirps); err != nil {
		// Log encoding errors
		log.Printf("Error encoding chirp: %s", err)
		// Send error response to client
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
func (cfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {
    chirpID, err := uuid.Parse(r.PathValue("chirpID"))
    if err != nil {
        log.Printf("Error parsing chirp ID: %s", err)
        http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
        return
    }
    
    chirp, err := cfg.DB.GetChirpByID(r.Context(), chirpID)
    if err != nil {
        log.Printf("Error getting chirp: %s", err)
        http.Error(w, "Chirp not found", http.StatusNotFound)
        return
    }

    responseChirp := Chirp{
        ID:        chirp.ID,
        CreatedAt: chirp.CreatedAt,
        UpdatedAt: chirp.UpdatedAt,
        Body:      chirp.Body,
        UserID:    chirp.UserID.UUID, // Extract UUID from NullUUID
    }




    // Send the response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(responseChirp)
}


func (cfg *apiConfig) refreshToken(w http.ResponseWriter, r *http.Request) {
	  // Define the structure for our JSON response
    // We only need to return the new JWT token
	type RefreshResponse struct {
		Token string `json:"token"`
	}
	// Extract the refresh token from the Authorization header
    // Format should be: "Bearer <token>"
	authHeader := r.Header.Get("Authorization")
    if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
        http.Error(w, "Missing or invalid token", http.StatusUnauthorized)
        return
    }
	// Remove the "Bearer " prefix to get just the token
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Look up the refresh token in the database
    // This gets us the associated user ID and expiration info
	 refreshToken, err := cfg.DB.GetRefreshToken(r.Context(), token)
	 if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}
	// Check if the token has been revoked
    // RevokedAt.Valid will be true if the token was revoked
	if refreshToken.RevokedAt.Valid {
		http.Error(w, "Token has been revoked", http.StatusUnauthorized)
		return
	}

   // Check if the token has expired by comparing current time
   // with the expiration timestamp from the database
	if time.Now().After(refreshToken.ExpiresAt) {
		http.Error(w, "Token has expired", http.StatusUnauthorized)
		return
	}

    // Create a new JWT access token for the user
    // Using the user ID from the refresh token
    // Setting expiration to 1 hour as specified
	jwtToken, err := auth.MakeJWT(refreshToken.UserID.UUID, cfg.jwSecret, time.Hour)
	if err != nil {
		http.Error(w, "Error creating jwtToken", http.StatusInternalServerError)
		return
	}
	response := RefreshResponse{
		Token: jwtToken,
	}
	respondWithJSON(w, http.StatusOK, response)
	
}

func (cfg *apiConfig) updateUsers(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid token", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	

	userID, err := auth.ValidateJWT(token, cfg.jwSecret)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return

	}

	type parameters struct {
		Email   string `json:"email"`
		Password string `json:"password"`

	}
	type userResponse struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}
	

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	params.Password, err = auth.HashPassword(params.Password)
	if err != nil{
		log.Printf("Error hashing password: %s", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
		
	}


	dbParams := database.UpdateUserParams{
		Email: params.Email,
		HashedPassword: params.Password,
		ID: userID,
	}
	updatedUser, err := cfg.DB.UpdateUser(r.Context(), dbParams)
if err != nil {
    // Handle the error appropriately
    log.Printf("Error updating user: %v", err)
    w.WriteHeader(http.StatusInternalServerError)
    return
}
response := userResponse{
    ID:        updatedUser.ID,
    CreatedAt: updatedUser.CreatedAt,
    UpdatedAt: updatedUser.UpdatedAt,
    Email:     updatedUser.Email,
}

w.Header().Set("Content-Type", "application/json")
w.WriteHeader(http.StatusOK)
json.NewEncoder(w).Encode(response)
}



func (cfg *apiConfig) revokeToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
        http.Error(w, "Missing or invalid token", http.StatusUnauthorized)
        return
    }
	token := strings.TrimPrefix(authHeader, "Bearer ")
	

	err := cfg.DB.UpdateRefresh(r.Context(), token)
	if err != nil {
		http.Error(w, "Failed updating token", http.StatusUnauthorized)
        return
	}

	w.WriteHeader(http.StatusNoContent)
}


func(cfg *apiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
        http.Error(w, "Missing or invalid token", http.StatusUnauthorized)
        return
    }
	token := strings.TrimPrefix(authHeader, "Bearer ")
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	userID, err := auth.ValidateJWT(token, cfg.jwSecret)
	if err != nil {
    http.Error(w, "Invalid token", http.StatusUnauthorized)
    return
	}

	chirp, err := cfg.DB.GetChirpByID(r.Context(), chirpID)
	if err != nil {
    http.Error(w, "Chirp not found", http.StatusNotFound)
    return
}
if chirp.UserID.UUID != userID {
    http.Error(w, "Unauthorized", http.StatusForbidden)
    return
}
	
err = cfg.DB.DeleteChirp(r.Context(), chirpID)
if err != nil {
    http.Error(w, "Failed to delete chirp", http.StatusInternalServerError)
    return
}

w.WriteHeader(http.StatusNoContent)


}

func(cfg *apiConfig) webhookHandler(w http.ResponseWriter, r *http.Request) {
	key, err := auth.GetAPIKey(r.Header)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	
	if key != cfg.PolkaKey{
		w.WriteHeader(http.StatusUnauthorized) // 401
		return
	}
	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}
	var params parameters
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
        // Handle error
        w.WriteHeader(http.StatusBadRequest)
        return
    }

	if params.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent) // 204
		return
	}

	userID, err := uuid.Parse(params.Data.UserID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}





	err = cfg.DB.UpgradeChirp(r.Context(), userID )
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Success! Return 204
	w.WriteHeader(http.StatusNoContent)

}


func main() {

	godotenv.Load()
	secret := os.Getenv("JWT_SECRET")
	dbURL := os.Getenv("DB_URL")
	polkaKey := os.Getenv("POLKA_KEY")
	if polkaKey == "" {
		log.Fatal("POLKA_KEY must be set")
	}
	
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Printf("Error opening connection to database: %s", err)
		return
	}
	dbQueries := database.New(db)

	mux := http.NewServeMux()
	apiCfg := &apiConfig{
		DB:       dbQueries,
		platform: os.Getenv("PLATFORM"),
		jwSecret: secret,
		PolkaKey: polkaKey,
	}

	fileServer := http.FileServer(http.Dir("."))
	handler := http.StripPrefix("/app", fileServer)

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(handler))
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirp)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUsers)
	mux.HandleFunc("POST /api/login", apiCfg.passwordVerify)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.webhookHandler)
	mux.HandleFunc("POST /api/users", apiCfg.createUserHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirpHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshToken)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeToken )

	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirp)
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
