package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Krelock/chirpy-server/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	DB *database.Queries // My database
	platform string
}
type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
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
        next.ServeHTTP(w, r)     // Pass the request to the next handler
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
	w.WriteHeader(http.StatusOK)     // Set 200 OK status
           // Write the response body



}

func removeProfane(text string) string {
    profaneWords := []string {"kerfuffle","sharbert", "fornax"}
	
	
	words := strings.Split(text, " ")
	
	for i := 0;  len(words) > i; i++ {
		lowerWord := strings.ToLower(words[i])
		for _, profaneWord := range profaneWords{
			if lowerWord == profaneWord {
				words[i] = "****"
				break
			}
		}
	}
	return strings.Join(words, " ")
}


func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	//cfg *apiConfig         | How we access the data base aka DB *database.Queries
	// w http.ResponseWriter | Sends data back can be accessed with w
	// r *http.Request       | Recives data can be accessed with r
	
	// Parameters for incoming data
    type parameters struct {
        Body   string `json:"body"`
        UserID string `json:"user_id"`
    }
    decoder := json.NewDecoder(r.Body)
    params := parameters{}
    err := decoder.Decode(&params)
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
    userID, err := uuid.Parse(params.UserID)
    if err != nil {
		log.Printf("Error finding user: %s", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
        return
    }
	// Parameters for outgoing data
	type chirpResponse struct {
		ID string `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body string `json:"body"`
		UserId string `json:"user_id"`

	}

	
// First define the params
chirp, err := cfg.DB.CreateChirp(r.Context(), database.CreateChirpParams{
    Body:   cleanedBody,  // your cleaned chirp text
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

func(cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
        Email string `json:"email"`
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

	dbUser, err := cfg.DB.CreateUser(r.Context(), params.Email)
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


// getAllChirps handles the GET /api/chirps endpoint
// It retrieves all chirps from the database and returns them as JSON
func(cfg *apiConfig) getAllChirps(w http.ResponseWriter, r *http.Request) {
    // Initialize an empty slice to store our response chirps
    chirps := []Chirp{}
    
    // Query the database for all chirps using the request's context
    list_of_chirps, err := cfg.DB.GetChirps(r.Context())
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
            UserID:    chirp.UserID.UUID,  // Extract UUID from NullUUID
        }
        // Add the transformed chirp to our response slice
        chirps = append(chirps, responseChirp)
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
func(cfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {
	
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		// Handle the error, e.g., log it and return an error response
		log.Printf("Error parsing chirp ID: %s", err)
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
}
	list_of_chirps, err := cfg.DB.GetChirps(r.Context())
	if err != nil {
		// Log the error for debugging purposes
		log.Printf("Error receiving chirps: %s", err)
		// Send an error response to the client
		http.Error(w, "Failed to retrieve chirps", http.StatusInternalServerError)
		return
	}
	for _, chirp := range list_of_chirps{
		if chirp.ID == chirpID {
			responseChirp := Chirp{
				ID:        chirpID,
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    chirp.UserID.UUID,  // Extract UUID from NullUUID
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(responseChirp); err != nil {
				// Log encoding errors
				log.Printf("Error encoding chirp: %s", err)
				// Send error response to client
				http.Error(w, "Failed to encode response", http.StatusInternalServerError)
				return
			}
			return
		}
	}

	http.Error(w, "Chirp not found", http.StatusNotFound)
	return

}


func main() {
	
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Printf("Error opening connection to database: %s", err)
		return
	}
	dbQueries := database.New(db)
	
	mux := http.NewServeMux()
	apiCfg := &apiConfig{
		DB: dbQueries,
		platform: os.Getenv("PLATFORM"),
	}

	fileServer := http.FileServer(http.Dir("."))
	handler := http.StripPrefix("/app", fileServer)
	
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(handler))
	mux.HandleFunc("POST /api/users", 		apiCfg.createUserHandler)
	mux.HandleFunc("POST /admin/reset", 	apiCfg.resetHandler)
	mux.HandleFunc("POST /api/chirps",  	apiCfg.createChirpHandler)
	mux.HandleFunc("GET /admin/metrics",	apiCfg.metricsHandler)
	mux.HandleFunc("GET /api/chirps", 		apiCfg.getAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirp)
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	server := http.Server{
		Addr:":8080",
		Handler: mux,
	}
	
	err = server.ListenAndServe()
	if err != nil {
    	log.Printf("Error starting server: %v", err)
}
}

