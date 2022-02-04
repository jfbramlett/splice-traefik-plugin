package splicetraefikplugin

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"text/template"

	"github.com/google/uuid"
)

const HeaderKey = "X-Request-Id"

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
	for key, value := range a.headers {
		tmpl, err := a.template.Parse(value)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		writer := &bytes.Buffer{}

		err = tmpl.Execute(writer, req)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		req.Header.Set(key, writer.String())
	}

	next = LoggingMiddleware(RequestIDMiddleware(SessionMiddleware(next)))

	next.ServeHTTP(rw, req)
}

func LoggingMiddleware(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Default().Printf("handling request: %s %s", r.Method, r.RequestURI)
		h.ServeHTTP(w, r)
		log.Default().Printf("completed request: %s %s", r.Method, r.RequestURI)
	}
}

func RequestIDMiddleware(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only generate a new request ID if it's not present in the Header
		if reqUUID := r.Header.Get(HeaderKey); reqUUID == "" {
			reqUUID = uuid.NewString()
			log.Default().Printf("assigning generated uuid to request: %s", reqUUID)
			r.Header.Set(HeaderKey, reqUUID)
		}

		h.ServeHTTP(w, r)
	}
}

func SessionMiddleware(h http.Handler) http.HandlerFunc {
	sessionMgr := NewSessionManager()
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := sessionMgr.UserFromRequest(r.Context(), r)
		if err != nil {
			log.Default().Printf("failed trying to get user from cookie: %s", err.Error())
		}
		log.Default().Printf("assigning user uuid and id: %s %d", user.UUID, user.ID)
		r.Header.Set("x-user-uuid", user.UUID)
		r.Header.Set("x-user-id", fmt.Sprint(user.ID))
		h.ServeHTTP(w, r)
	}
}
