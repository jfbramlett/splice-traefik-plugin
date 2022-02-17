package splicetraefikplugin

import (
	"context"
	"log"
	"net/http"
	"text/template"
)

// Config the plugin configuration.
type Config struct {
	Headers map[string]string `json:"headers,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Headers: make(map[string]string),
	}
}

// Splice the custom splice plugin
type Splice struct {
	next     http.Handler
	headers  map[string]string
	name     string
	template *template.Template
}

// New created a new Demo plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Splice{
		headers:  config.Headers,
		next:     next,
		name:     name,
		template: template.New("demo").Delims("[[", "]]"),
	}, nil
}

func (a *Splice) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	next := a.next

	next = LoggingMiddleware(next)

	next.ServeHTTP(rw, req)
}

func LoggingMiddleware(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Default().Printf("handling request: %s %s", r.Method, r.RequestURI)
		h.ServeHTTP(w, r)
		log.Default().Printf("completed request: %s %s", r.Method, r.RequestURI)
	}
}
