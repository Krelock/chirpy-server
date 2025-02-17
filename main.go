package main

import (
	"net/http"
	"sync/atomic"
	"fmt"
	"encoding/json"
	"log"
	"strings"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cfg.fileserverHits.Add(1) // Increment the counter safely
        next.ServeHTTP(w, r)     // Pass the request to the next handler
    })
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, _ *http.Request) {
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


func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
    type parameters struct {
        // these tags indicate how the keys in the JSON should be mapped to the struct fields
        // the struct fields must be exported (start with a capital letter) if you want them parsed
        Body string `json:"body"`
    }

    decoder := json.NewDecoder(r.Body)
    params := parameters{}
    err := decoder.Decode(&params)
    if err != nil {
        // an error will be thrown if the JSON is invalid or has the wrong types
        // any missing fields will simply have their values in the struct set to their zero value
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
    }
    // params is a struct with data populated successfully
    // ...
	type errorResponse struct {
		Error string `json:"error"`
	}
	
	type validResponse struct {
		CleanedBody string `json:"cleaned_body"`
	}
	
	errResp := errorResponse{
		Error: "Chirp is too long",
	}
	cleanedResp := validResponse{
		// Removes the profane words from the parameters struct and replaces them with **** no matter the length
		CleanedBody: removeProfane(params.Body),
		
	}
	if len(params.Body) <= 140{
		dat, err := json.Marshal(cleanedResp)

		if err != nil {
			log.Printf("Error marshalling VALID: %s", err)
			w.WriteHeader(500) // 500 means server error
			return
		
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200) // 200 means succuess
		w.Write(dat)

	} else {
		dat, err := json.Marshal(errResp)
		if err != nil {
			log.Printf("Error marshalling ERROR: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400) // 400 means client error
		w.Write(dat)

	}
}




func main() {
	mux := http.NewServeMux()
	apiCfg := &apiConfig{}
	
	fileServer := http.FileServer(http.Dir("."))
	handler :=  http.StripPrefix("/app", fileServer)
	
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(handler))
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	server := http.Server{
		Addr:":8080",
		Handler: mux,
	}
	
	server.ListenAndServe()
}

