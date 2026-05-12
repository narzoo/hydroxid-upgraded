package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/emersion/hydroxide/config"
	"github.com/emersion/hydroxide/protonmail"
)

func authFilePath() (string, error) {
	return config.Path("auth.json")
}

type CachedAuth struct {
	protonmail.Auth
	LoginPassword         string
	MailboxPassword       string
	KeySalts              map[string][]byte
	DisablePasswordReauth bool
	// TODO: add padding
}

func DecodeBridgePassword(password string) (*[32]byte, error) {
	var secretKey [32]byte
	passwordBytes, err := base64.StdEncoding.DecodeString(password)
	if err != nil || len(passwordBytes) != len(secretKey) {
		return nil, ErrUnauthorized
	}
	copy(secretKey[:], passwordBytes)
	return &secretKey, nil
}

func LoadCachedAuth(username, bridgePassword string) (*CachedAuth, *[32]byte, error) {
	secretKey, err := DecodeBridgePassword(bridgePassword)
	if err != nil {
		return nil, nil, err
	}

	auths, err := readCachedAuths()
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, err
	}

	encrypted, ok := auths[username]
	if !ok {
		return nil, nil, ErrUnauthorized
	}

	decrypted, err := decrypt(encrypted, secretKey)
	if err != nil {
		return nil, nil, ErrUnauthorized
	}

	var cachedAuth CachedAuth
	if err := json.Unmarshal(decrypted, &cachedAuth); err != nil {
		return nil, nil, err
	}

	return &cachedAuth, secretKey, nil
}

func ExportCachedAuth(username, bridgePassword string, includePasswords bool) (*CachedAuth, error) {
	cachedAuth, _, err := LoadCachedAuth(username, bridgePassword)
	if err != nil {
		return nil, err
	}

	exported := *cachedAuth
	if !includePasswords {
		exported.LoginPassword = ""
		exported.DisablePasswordReauth = true
	}

	return &exported, nil
}

func ImportCachedAuth(username string, cachedAuth *CachedAuth, secretKey *[32]byte) error {
	if cachedAuth == nil {
		return errors.New("cached auth is required")
	}

	if cachedAuth.RefreshToken == "" || cachedAuth.UID == "" {
		return errors.New("cached auth must contain at least UID and refresh token")
	}

	return EncryptAndSave(cachedAuth, username, secretKey)
}

func Verify(newClient func() *protonmail.Client, username, bridgePassword string) (*CachedAuth, error) {
	cachedAuth, secretKey, err := LoadCachedAuth(username, bridgePassword)
	if err != nil {
		return nil, err
	}

	c := newClient()
	if _, err := authenticate(c, cachedAuth, username); err != nil {
		return nil, err
	}

	if err := EncryptAndSave(cachedAuth, username, secretKey); err != nil {
		return nil, err
	}

	return cachedAuth, nil
}

func readCachedAuths() (map[string]string, error) {
	p, err := authFilePath()
	if err != nil {
		return nil, fmt.Errorf("failed to get auth file path: %v", err)
	}

	f, err := os.Open(p)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to open cached auth file: %v", err)
	}
	defer f.Close()

	auths := make(map[string]string)
	if err := json.NewDecoder(f).Decode(&auths); err != nil {
		return nil, fmt.Errorf("failed to read cached auth file: %v", err)
	}

	return auths, nil
}

func saveAuths(auths map[string]string) error {
	p, err := authFilePath()
	if err != nil {
		return fmt.Errorf("failed to get auth file path: %v", err)
	}
	f, err := os.Create(p)
	if err != nil {
		return fmt.Errorf("failed to create cached auth file: %v", err)
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(auths); err != nil {
		return fmt.Errorf("failed to write cached auth file: %v", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close cached auth file: %v", err)
	}
	return nil
}

func encrypt(msg []byte, secretKey *[32]byte) (string, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	encrypted := secretbox.Seal(nonce[:], msg, &nonce, secretKey)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func decrypt(encryptedString string, secretKey *[32]byte) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(encryptedString)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted string: %v", err)
	}

	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &nonce, secretKey)
	if !ok {
		return nil, errors.New("decryption error")
	}
	return decrypted, nil
}

func EncryptAndSave(auth *CachedAuth, username string, secretKey *[32]byte) error {
	cleartext, err := json.Marshal(auth)
	if err != nil {
		return fmt.Errorf("failed to format cached auth: %v", err)
	}

	encrypted, err := encrypt(cleartext, secretKey)
	if err != nil {
		return err
	}

	auths, err := readCachedAuths()
	if err != nil {
		return err
	}

	if auths == nil {
		auths = make(map[string]string)
	}
	auths[username] = encrypted

	return saveAuths(auths)
}

func authenticate(c *protonmail.Client, cachedAuth *CachedAuth, username string) (openpgp.EntityList, error) {
	auth, err := c.AuthRefresh(&cachedAuth.Auth)
	if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.Code == 10013 {
		if cachedAuth.DisablePasswordReauth {
			return nil, fmt.Errorf("cannot re-authenticate automatically: refresh token is invalid and password re-auth is disabled")
		}
		if cachedAuth.LoginPassword == "" {
			return nil, fmt.Errorf("cannot re-authenticate automatically: refresh token is invalid and no login password is cached")
		}
		// Invalid refresh token, re-authenticate
		authInfo, err := c.AuthInfo(username)
		if err != nil {
			return nil, fmt.Errorf("cannot re-authenticate: failed to get auth info: %v", err)
		}

		auth, err = c.Auth(username, cachedAuth.LoginPassword, authInfo)
		if err != nil {
			return nil, fmt.Errorf("cannot re-authenticate: %v", err)
		}

		if auth.TwoFactor.Enabled != 0 {
			return nil, fmt.Errorf("cannot re-authenticate: two factor authentication enabled, please login again manually")
		}
	} else if err != nil {
		return nil, err
	}
	cachedAuth.Auth = *auth

	return c.Unlock(auth, cachedAuth.KeySalts, cachedAuth.MailboxPassword)
}

func ListUsernames() ([]string, error) {
	auths, err := readCachedAuths()
	if err != nil {
		return nil, err
	}

	l := make([]string, 0, len(auths))
	for username, _ := range auths {
		l = append(l, username)
	}
	return l, nil
}

func GeneratePassword() (secretKey *[32]byte, password string, err error) {
	var key [32]byte
	if _, err = io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, "", fmt.Errorf("failed to generate key: %v", err)
	}
	password = base64.StdEncoding.EncodeToString(key[:])
	return &key, password, nil
}

type session struct {
	hashedSecretKey []byte
	c               *protonmail.Client
	privateKeys     openpgp.EntityList
}

var ErrUnauthorized = errors.New("Invalid username or password")

type Manager struct {
	newClient func() *protonmail.Client
	sessions  map[string]*session
}

func (m *Manager) Auth(username, password string) (*protonmail.Client, openpgp.EntityList, error) {
	secretKey, err := DecodeBridgePassword(password)
	if err != nil {
		return nil, nil, ErrUnauthorized
	}

	s, ok := m.sessions[username]
	if ok {
		err := bcrypt.CompareHashAndPassword(s.hashedSecretKey, secretKey[:])
		if err != nil {
			return nil, nil, ErrUnauthorized
		}
	} else {
		cachedAuth, _, err := LoadCachedAuth(username, password)
		if err != nil {
			return nil, nil, err
		}

		c := m.newClient()
		c.ReAuth = func() error {
			if _, err := authenticate(c, cachedAuth, username); err != nil {
				return err
			}
			return EncryptAndSave(cachedAuth, username, secretKey)
		}

		// authenticate updates cachedAuth with the new refresh token
		privateKeys, err := authenticate(c, cachedAuth, username)
		if err != nil {
			return nil, nil, err
		}

		if err := EncryptAndSave(cachedAuth, username, secretKey); err != nil {
			return nil, nil, err
		}

		hashed, err := bcrypt.GenerateFromPassword(secretKey[:], bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, err
		}

		s = &session{
			c:               c,
			privateKeys:     privateKeys,
			hashedSecretKey: hashed,
		}
		m.sessions[username] = s
	}

	return s.c, s.privateKeys, nil
}

func NewManager(newClient func() *protonmail.Client) *Manager {
	return &Manager{
		newClient: newClient,
		sessions:  make(map[string]*session),
	}
}
