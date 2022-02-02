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

	_, err := i.Eval(`import "crypto/hmac"`)
	if err != nil {
		panic(err)
	}
	_, err = i.Eval(`import "crypto/sha1"`)
	if err != nil {
		panic(err)
	}
	_, err = i.Eval(`import "fmt"`)
	if err != nil {
		panic(err)
	}
	_, err = i.Eval(`prf := hmac.New(sha1.New, []byte("this is a test"))
	hashLen := prf.Size()
	numBlocks := (32 + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write([]byte("salt"))
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF([]byte("this is a test"), U_(n-1))
		for n := 2; n <= 1000; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}

	fmt.Println(dk[:32])
`)
	if err != nil {
		panic(err)
	}

}
