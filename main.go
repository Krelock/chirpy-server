package main

import (
	"net/http"
	"sync/atomic"
	"fmt"
	
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
    response := fmt.Sprintf("Hits: %d", hits)
    w.WriteHeader(http.StatusOK)     // Set 200 OK status
    w.Write([]byte(response))        // Write the response body
}



func main() {
	mux := http.NewServeMux()
	apiCfg := &apiConfig{}
	
	fileServer := http.FileServer(http.Dir("."))
	handler :=  http.StripPrefix("/app", fileServer)
	
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(handler))
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /api/reset", apiCfg.resetHandler)
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

