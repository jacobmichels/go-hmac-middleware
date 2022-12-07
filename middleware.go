package hmacmiddleware

import "net/http"

// Returns the middleware function to verify an hmac signature
// The middleware retrieves the hmac signature from a header
func GetVerifyHMACFunc(key []byte, getSig func(*http.Request) ([]byte, error), getMsg func(*http.Request) ([]byte, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sig, err := getSig(r)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			msg, err := getMsg(r)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if !verify(msg, key, sig) {
				w.WriteHeader(http.StatusUnauthorized)
			}

			next.ServeHTTP(w, r)
		})
	}
}
