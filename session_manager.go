package splicetraefikplugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	AnonymousUserUUID = "ee2c2da9-889f-4741-9577-118428a87609"
	AnonymousUserID   = 0
)

var AnonymousUser = User{ID: AnonymousUserID, UUID: AnonymousUserUUID}

type User struct {
	ID   int
	UUID string
}

type SessionManager struct {
	cookieName    string
	sessionCrypt  *MessageEncryptor
	sessionSecret string
}

func NewSessionManager(cookieName string, sessionSecret string) *SessionManager {
	if cookieName == "" {
		cookieName = os.Getenv("RAILS_COOKIE_NAME")
	}
	if sessionSecret == "" {
		sessionSecret = os.Getenv("RAILS_SECRET")
	}

	var sessionCrypt *MessageEncryptor
	if sessionSecret != "" {
		sessionCrypt = createEncryptor(sessionSecret, []byte("encrypted cookie"), []byte("signed encrypted cookie"))
	}

	return &SessionManager{sessionCrypt: sessionCrypt, cookieName: cookieName, sessionSecret: sessionSecret}
}

type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	HttpOnly bool   `json:"http_only"`
	Secure   bool   `json:"secure"`
	MaxAge   int    `json:"max_age"`
	Expires  int64  `json:"expires_at"`
}

func (c *SessionManager) UserFromRequest(ctx context.Context, request *http.Request) (User, error) {
	cookieHeader := request.Header.Get("cookie")
	log.Default().Printf("read cookies: %s", cookieHeader)
	return c.UserFromHeader(ctx, cookieHeader)
}
func (c *SessionManager) UserFromHeader(ctx context.Context, headerCookie string) (User, error) {
	cookiesList := strings.Split(headerCookie, "; ")
	for _, cookie := range cookiesList {
		log.Default().Printf("cookie value: %s", cookie)
		if strings.HasPrefix(cookie, "{") {
			usr, err := c.userFromJsonCookie(ctx, cookie)
			if err != nil {
				continue
			}
			return usr, nil
		} else {
			usr, err := c.userFromStringCookie(ctx, cookie)
			if err != nil {
				continue
			}
			return usr, nil
		}
	}

	return AnonymousUser, errors.New("failed to find a valid cookie")
}

func (c *SessionManager) userFromStringCookie(ctx context.Context, cookie string) (User, error) {

	var sessionCookie string
	cookieMatch := strings.ToLower(fmt.Sprintf("%s=", c.cookieName))
	if strings.HasPrefix(strings.ToLower(cookie), cookieMatch) {
		sessionCookie = strings.ReplaceAll(cookie, cookieMatch, "")
		sessionCookieParts := strings.Split(sessionCookie, ",")
		if len(sessionCookieParts) > 0 {
			sessionCookie = sessionCookieParts[0]
		}
	}
	if sessionCookie == "" {
		return AnonymousUser, errors.New("failed to find session cookie")
	}

	usr, err := c.userFromCookie(ctx, sessionCookie)
	if err != nil {
		return AnonymousUser, fmt.Errorf("failed to get user from cookie %s: %s", sessionCookie, err.Error())
	}
	return usr, nil
}

func (c *SessionManager) userFromJsonCookie(ctx context.Context, headerCookies string) (User, error) {
	var result map[string][]*Cookie

	if !strings.HasSuffix(headerCookies, "}") {
		headerCookies = headerCookies[:strings.LastIndex(headerCookies, "}")+1]
	}

	// Unmarshal or Decode the JSON to the interface.
	err := json.Unmarshal([]byte(headerCookies), &result)
	if err != nil {
		return AnonymousUser, fmt.Errorf("failed to reader cookie json %s: %s", headerCookies, err.Error())
	}

	sessionCookies, found := result[c.cookieName]
	if !found {
		return AnonymousUser, fmt.Errorf("failed to find cookie %s in %s", c.cookieName, headerCookies)
	}
	log.Default().Printf("found session cookie %s", c.cookieName)

	var sessionCookie *Cookie
	for _, sc := range sessionCookies {
		if sc.Name == c.cookieName {
			sessionCookie = sc
			break
		}
	}

	if sessionCookie == nil {
		return AnonymousUser, fmt.Errorf("failed to find cookie %s in cookie %v", c.cookieName, sessionCookie)
	}
	return c.userFromCookie(ctx, sessionCookie.Value)
}

func (c *SessionManager) userFromCookie(_ context.Context, cookieValue string) (User, error) {
	if c.sessionCrypt == nil {
		return AnonymousUser, nil
	}
	log.Default().Printf("processing cookie value %s", cookieValue)

	var err error
	cookieValue, err = url.QueryUnescape(cookieValue)
	if err != nil {
		return AnonymousUser, err
	}

	log.Default().Printf("decrypting and verifying cookie value %s", cookieValue)

	var session Session
	err = c.sessionCrypt.DecryptAndVerify(cookieValue, &session)
	if err != nil {
		return AnonymousUser, fmt.Errorf("failed decrypting cookie: %s", err.Error())
	}

	userID := session.UserID()
	userUUID := session.UserUUID()

	return User{ID: userID, UUID: userUUID}, nil
}

func createEncryptor(keySecret string, secretSalt, signSalt []byte) *MessageEncryptor {
	secret := Key([]byte(keySecret), secretSalt, 1000, 32)
	signSecret := Key([]byte(keySecret), signSalt, 1000, 64)
	return &MessageEncryptor{Key: secret, SignKey: signSecret}
}

type Session struct {
	SessionId string `json:"session_id"`
	CsrfToken string `json:"_csrf_token,omitempty"`
	// [[1], "$2a$10$x.Z3QqY7QUoULBbyb6wbR."]
	WardenUserData []json.RawMessage `json:"warden.user.user.key,omitempty"`
	userID         *int
	// userSalt includes the bcrypt code, cost and salt
	userSalt string //nolint
	userUUID string
}

func (s *Session) UserID() int {
	if s == nil {
		return AnonymousUserID
	}
	if s.userID != nil {
		return *s.userID
	}
	if len(s.WardenUserData) > 0 {
		var id []int
		if err := json.Unmarshal(s.WardenUserData[0], &id); err != nil {
			return 0
		}
		if len(id) > 0 {
			s.userID = &id[0]
			return *s.userID
		}
	}
	return AnonymousUserID
}

func (s *Session) UserUUID() string {
	if s == nil {
		return AnonymousUserUUID
	}
	if s.userUUID != "" {
		return s.userUUID
	}
	if len(s.WardenUserData) > 1 {
		var uuids []string
		if err := json.Unmarshal(s.WardenUserData[2], &uuids); err != nil {
			return AnonymousUserUUID
		}
		if len(uuids) > 0 {
			s.userUUID = uuids[0]
			return s.userUUID
		}
	}
	return AnonymousUserUUID
}
