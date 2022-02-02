package splicetraefikplugin_test

import (
	"context"
	"github.com/jfbramlett/splicetraefikplugin"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDemo(t *testing.T) {
	cfg := splicetraefikplugin.CreateConfig()
	cfg.Headers["X-Host"] = "[[.Host]]"
	cfg.Headers["X-Method"] = "[[.Method]]"
	cfg.Headers["X-URL"] = "[[.URL]]"
	cfg.Headers["X-URL"] = "[[.URL]]"
	cfg.Headers["X-Demo"] = "test"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := splicetraefikplugin.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "X-Host", "localhost")
	assertHeader(t, req, "X-URL", "http://localhost")
	assertHeader(t, req, "X-Method", "GET")
	assertHeader(t, req, "X-Demo", "test")
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}

func TestYaegi(t *testing.T) {
	i := interp.New(interp.Options{GoPath: "/Users/johnbramlett/go/src/github.com/jfbramlett/splicetraefikplugin/vendor"})
	i.Use(stdlib.Symbols)

	_, err := i.Eval(`import "golang.org/x/crypto/pbkdf2"`)
	if err != nil {
		panic(err)
	}
	_, err = i.Eval(`import ""crypto/sha1""`)
	if err != nil {
		panic(err)
	}

	_, err = i.Eval(`secret := pbkdf2.Key([]byte("hello world"), []byte("my salt"), 1000, 32, sha1.New)`)
	if err != nil {
		panic(err)
	}

	_, err = i.Eval(`fmt.Println(secret)`)
	if err != nil {
		panic(err)
	}

}
