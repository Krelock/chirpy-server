package auth

// have to add stuff to go.mod when you need imports that arent in default go
import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	// []byte turns the string into a byte so the function can use it
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) error {

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	// Create an instance of jwt.RegisteredClaims with the required fields.
	claims := &jwt.RegisteredClaims{
		Issuer:    "chirpy",                                      // Set the issuer of the token, identifying the issuing service.
		IssuedAt:  jwt.NewNumericDate(time.Now()),                // Set the issued-at time to the current time in UTC.
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)), // Set the expiration time based on the duration provided.
		Subject:   userID.String(),                               // Set the subject to the user ID as a string.
	}

	// Create a new token object with the specified claims and signing method (HS256 in this case).
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token using the provided secret key, returning the complete token string.
	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		// If an error occurs during signing, return the error with an empty token string.
		return "", err
	}

	// Return the signed token string and nil for error when no issues arose.
	return tokenString, nil
}

// When your server issues a JWT to Bob, Bob can use that token to make requests as Bob to your API.
// Bob won't be able to change the token to make requests as Alice.
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {

	// Define a key function to provide the signing secret for token parsing.
	// This function receives the token and returns the secret key.
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil // Always return the token secret as a byte slice.
	}

	// Parse the JWT token string, specifying `&jwt.RegisteredClaims{}` as the expected claims structure
	// and using the key function to validate the signature.
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, keyFunc)
	if err != nil {
		return uuid.Nil, err
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		// If the type assertion fails, return an error.
		return uuid.Nil, fmt.Errorf("invalid token claims type")
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		// Handle the case where the Subject field is not a valid UUID string.
		return uuid.Nil, fmt.Errorf("invalid UUID in token subject: %w", err)
	}
	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		// Now `token` holds the token string.
		return token, nil

	} else {
		return "", fmt.Errorf("invalid bearer header")
	}

}


func MakeRefreshToken() (string, error) {
	// fill key with secure random bytes
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	encodedStr := hex.EncodeToString(key)
	return encodedStr, nil
}

func GetAPIKey(headers http.Header) (string, error) {
	
	authHeader := headers.Get("Authorization")  

	if authHeader == "" || !strings.HasPrefix(authHeader, "ApiKey ") {
		return "", fmt.Errorf("Failed to find authorization header")  
    }

	apiKey := strings.TrimPrefix(authHeader, "ApiKey ")
	if apiKey == "" {
		return "", fmt.Errorf("API key not found in header")
	}

	return apiKey, nil


}