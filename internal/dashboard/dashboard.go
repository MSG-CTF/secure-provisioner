package dashboard

import (
	_ "embed"
	"net/http"
)

//go:embed web/index.html
var indexHTML []byte

func Handler(api http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/internal/", api)
	mux.HandleFunc("GET /{$}", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(indexHTML)
	})
	return mux
}
