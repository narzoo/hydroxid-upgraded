package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	imapserver "github.com/emersion/go-imap/server"
	"github.com/emersion/go-mbox"
	"github.com/emersion/go-smtp"
	"golang.org/x/term"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/carddav"
	"github.com/emersion/hydroxide/config"
	"github.com/emersion/hydroxide/events"
	"github.com/emersion/hydroxide/exports"
	imapbackend "github.com/emersion/hydroxide/imap"
	"github.com/emersion/hydroxide/imports"
	"github.com/emersion/hydroxide/protonmail"
	smtpbackend "github.com/emersion/hydroxide/smtp"
)

const (
	defaultAPIEndpoint = "https://mail.proton.me/api"
	defaultAppVersion  = "Other"
	defaultHTTPTimeout = 35 * time.Second
)

var (
	debug        bool
	apiEndpoint  string
	appVersion   string
	bridgeHealth = &bridgeHealthMonitor{}
)

func newClient() *protonmail.Client {
	return &protonmail.Client{
		RootURL:    apiEndpoint,
		AppVersion: appVersion,
		Debug:      debug,
		// Bound every Proton API request so a dead Tor circuit cannot pin an IMAP session forever.
		HTTPClient:     &http.Client{Timeout: defaultHTTPTimeout},
		ResultObserver: bridgeHealth.observe,
	}
}

const (
	bridgeRecoveryFailureThreshold = 6
	bridgeRecoveryMinimumAge       = 3 * time.Minute
)

type bridgeHealthMonitor struct {
	mu               sync.Mutex
	consecutiveFails int
	firstFailureAt   time.Time
	lastSuccessAt    time.Time
}

func isRecoverableBridgeError(req *http.Request, err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())
	if strings.Contains(message, "timeout") || strings.Contains(message, "deadline exceeded") || strings.Contains(message, "unexpected eof") || strings.Contains(message, "invalid character '<'") {
		return true
	}

	apiErr, ok := err.(*protonmail.APIError)
	return ok && apiErr.Code >= 500 && apiErr.Code < 600 && req != nil && strings.HasPrefix(req.URL.Path, "/api/events/")
}

func (m *bridgeHealthMonitor) observe(req *http.Request, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err == nil {
		m.consecutiveFails = 0
		m.firstFailureAt = time.Time{}
		m.lastSuccessAt = time.Now()
		return
	}

	if !isRecoverableBridgeError(req, err) {
		return
	}

	if m.firstFailureAt.IsZero() {
		m.firstFailureAt = time.Now()
	}
	m.consecutiveFails++
}

func (m *bridgeHealthMonitor) shouldRestart(now time.Time) (int, time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.consecutiveFails < bridgeRecoveryFailureThreshold || m.firstFailureAt.IsZero() || m.lastSuccessAt.After(m.firstFailureAt) {
		return 0, 0, false
	}

	age := now.Sub(m.firstFailureAt)
	return m.consecutiveFails, age, age >= bridgeRecoveryMinimumAge
}

func runBridgeRecoveryWatchdog() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for now := range ticker.C {
		failures, age, restart := bridgeHealth.shouldRestart(now)
		if !restart {
			continue
		}

		log.Printf("BRIDGE_SELF_RECOVERY: restarting Hydroxide after %d consecutive recoverable API failures over %s", failures, age.Round(time.Second))
		os.Exit(75)
	}
}

func askPass(prompt string) ([]byte, error) {
	f := os.Stdin
	if !term.IsTerminal(int(f.Fd())) {
		// This can happen if stdin is used for piping data
		// TODO: the following assumes Unix
		var err error
		if f, err = os.Open("/dev/tty"); err != nil {
			return nil, err
		}
		defer f.Close()
	}
	fmt.Fprintf(os.Stderr, "%v: ", prompt)
	b, err := term.ReadPassword(int(f.Fd()))
	if err == nil {
		fmt.Fprintf(os.Stderr, "\n")
	}
	return b, err
}

func askBridgePass() (string, error) {
	if v := os.Getenv("HYDROXIDE_BRIDGE_PASS"); v != "" {
		return v, nil
	}
	b, err := askPass("Bridge password")
	return string(b), err
}

func ask(prompt string) (string, error) {
	f := os.Stdin
	if !term.IsTerminal(int(f.Fd())) {
		var err error
		if f, err = os.Open("/dev/tty"); err != nil {
			return "", err
		}
		defer f.Close()
	}

	fmt.Fprintf(os.Stderr, "%v: ", prompt)
	reader := bufio.NewReader(f)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func completeHumanVerification(c *protonmail.Client, username, loginPassword string, apiErr *protonmail.APIError) (*protonmail.Auth, error) {
	hvDetails, err := apiErr.GetHVDetails()
	if err != nil {
		return nil, fmt.Errorf("human verification requested but details could not be parsed: %v", err)
	}

	verifyURL := hvDetails.VerifyURL()
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Human verification required.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Steps:")
	fmt.Fprintln(os.Stderr, "  1. Open your browser's Developer Tools (F12)")
	fmt.Fprintln(os.Stderr, "  2. Go to the Console tab and paste this snippet:")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, `     window.addEventListener("message", e => { if (e.data?.type === "pm_captcha" && e.data.token) prompt("Copy this token:", e.data.token) })`)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  3. Open this URL and solve the verification challenge:")
	fmt.Fprintf(os.Stderr, "     %s\n", verifyURL)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  4. When the browser prompt shows the token, paste it below")
	fmt.Fprintln(os.Stderr, "")

	for attempt := 1; attempt <= 3; attempt++ {
		solvedToken, err := ask(fmt.Sprintf("Solved token (attempt %d/3)", attempt))
		if err != nil {
			return nil, err
		}
		if solvedToken == "" {
			return nil, fmt.Errorf("human verification cancelled: empty solved token")
		}

		retryInfo, err := c.AuthInfo(username)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth info for verification retry: %v", err)
		}

		authData, err := c.AuthWithHV(username, loginPassword, retryInfo, hvDetails.SolvedCopy(solvedToken))
		if err == nil {
			return authData, nil
		}

		retryAPIError, ok := err.(*protonmail.APIError)
		if !ok {
			return nil, err
		}

		if retryAPIError.Code == protonmail.HumanValidationInvalidToken {
			fmt.Fprintln(os.Stderr, "Solved token was not accepted. Please retry with a fresh token from the browser prompt.")
			continue
		}

		if retryAPIError.IsHVError() {
			if refreshedDetails, detailsErr := retryAPIError.GetHVDetails(); detailsErr == nil && refreshedDetails.Token != "" {
				hvDetails = refreshedDetails
				if nextURL := hvDetails.VerifyURL(); nextURL != "" && nextURL != verifyURL {
					verifyURL = nextURL
					fmt.Fprintln(os.Stderr, "Proton requested a fresh verification challenge. Open this updated URL:")
					fmt.Fprintf(os.Stderr, "  %s\n", verifyURL)
				}
			}
			fmt.Fprintln(os.Stderr, "Verification challenge still active. Please solve it again and paste the new token.")
			continue
		}

		return nil, err
	}

	return nil, fmt.Errorf("human verification failed after 3 attempts")
}

func listenAndServeSMTP(addr string, debug bool, authManager *auth.Manager, tlsConfig *tls.Config) error {
	be := smtpbackend.New(authManager)
	s := smtp.NewServer(be)
	s.Addr = addr
	s.Domain = "localhost" // TODO: make this configurable
	s.AllowInsecureAuth = tlsConfig == nil
	s.TLSConfig = tlsConfig
	if debug {
		s.Debug = os.Stdout
	}

	if s.TLSConfig != nil {
		log.Println("SMTP server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS()
	}

	log.Println("SMTP server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeIMAP(addr string, debug bool, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	be := imapbackend.New(authManager, eventsManager)
	s := imapserver.New(be)
	s.Addr = addr
	s.AllowInsecureAuth = tlsConfig == nil
	s.TLSConfig = tlsConfig
	if debug {
		s.Debug = os.Stdout
	}

	if s.TLSConfig != nil {
		log.Println("IMAP server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS()
	}

	log.Println("IMAP server listening on", s.Addr)
	return s.ListenAndServe()
}

func listenAndServeCardDAV(addr string, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	handlers := make(map[string]http.Handler)

	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			resp.Header().Set("WWW-Authenticate", "Basic")

			username, password, ok := req.BasicAuth()
			if !ok {
				resp.WriteHeader(http.StatusUnauthorized)
				io.WriteString(resp, "Credentials are required")
				return
			}

			c, privateKeys, err := authManager.Auth(username, password)
			if err != nil {
				if err == auth.ErrUnauthorized {
					resp.WriteHeader(http.StatusUnauthorized)
				} else {
					resp.WriteHeader(http.StatusInternalServerError)
				}
				io.WriteString(resp, err.Error())
				return
			}

			h, ok := handlers[username]
			if !ok {
				ch := make(chan *protonmail.Event)
				eventsManager.Register(c, username, ch, nil)
				h = carddav.NewHandler(c, privateKeys, ch)

				handlers[username] = h
			}

			h.ServeHTTP(resp, req)
		}),
	}

	if s.TLSConfig != nil {
		log.Println("CardDAV server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS("", "")
	}

	log.Println("CardDAV server listening on", s.Addr)
	return s.ListenAndServe()
}

func isMbox(br *bufio.Reader) (bool, error) {
	prefix := []byte("From ")
	b, err := br.Peek(len(prefix))
	if err != nil {
		return false, err
	}
	return bytes.Equal(b, prefix), nil
}

const usage = `usage: hydroxide [options...] <command>
Commands:
	auth <username>		Login to ProtonMail via hydroxide
	auth-export <username> [file]	Export cached auth state
	auth-import <username> [file]	Import cached auth state
	auth-verify <username>	Verify cached auth state
	carddav			Run hydroxide as a CardDAV server
	export-secret-keys <username> Export secret keys
	imap			Run hydroxide as an IMAP server
	import-messages <username> [file]	Import messages
	export-messages [options...] <username>	Export messages
	sendmail <username> -- <args...>	sendmail(1) interface
	serve			Run all servers
	smtp			Run hydroxide as an SMTP server
	status			View hydroxide status

Global options:
	-debug
		Enable debug logs
	-api-endpoint <url>
		ProtonMail API endpoint
	-app-version <version>
		ProtonMail application version
	-smtp-host example.com
		Allowed SMTP email hostname on which hydroxide listens, defaults to 127.0.0.1
	-imap-host example.com
		Allowed IMAP email hostname on which hydroxide listens, defaults to 127.0.0.1
	-carddav-host example.com
		Allowed SMTP email hostname on which hydroxide listens, defaults to 127.0.0.1
	-smtp-port example.com
		SMTP port on which hydroxide listens, defaults to 1025
	-imap-port example.com
		IMAP port on which hydroxide listens, defaults to 1143
	-carddav-port example.com
		CardDAV port on which hydroxide listens, defaults to 8080
	-disable-imap
		Disable IMAP for hydroxide serve
	-disable-smtp
		Disable SMTP for hydroxide serve
	-disable-carddav
		Disable CardDAV for hydroxide serve
	-tls-cert /path/to/cert.pem
		Path to the certificate to use for incoming connections (Optional)
	-tls-key /path/to/key.pem
		Path to the certificate key to use for incoming connections (Optional)
	-tls-client-ca /path/to/ca.pem
		If set, clients must provide a certificate signed by the given CA (Optional)

Environment variables:
	HYDROXIDE_BRIDGE_PASS	Don't prompt for the bridge password, use this variable instead
`

func main() {
	flag.BoolVar(&debug, "debug", false, "Enable debug logs")
	flag.StringVar(&apiEndpoint, "api-endpoint", defaultAPIEndpoint, "ProtonMail API endpoint")
	flag.StringVar(&appVersion, "app-version", defaultAppVersion, "ProtonMail app version")

	smtpHost := flag.String("smtp-host", "127.0.0.1", "Allowed SMTP email hostname on which hydroxide listens, defaults to 127.0.0.1")
	smtpPort := flag.String("smtp-port", "1025", "SMTP port on which hydroxide listens, defaults to 1025")
	disableSMTP := flag.Bool("disable-smtp", false, "Disable SMTP for hydroxide serve")

	imapHost := flag.String("imap-host", "127.0.0.1", "Allowed IMAP email hostname on which hydroxide listens, defaults to 127.0.0.1")
	imapPort := flag.String("imap-port", "1143", "IMAP port on which hydroxide listens, defaults to 1143")
	disableIMAP := flag.Bool("disable-imap", false, "Disable IMAP for hydroxide serve")

	carddavHost := flag.String("carddav-host", "127.0.0.1", "Allowed CardDAV email hostname on which hydroxide listens, defaults to 127.0.0.1")
	carddavPort := flag.String("carddav-port", "8080", "CardDAV port on which hydroxide listens, defaults to 8080")
	disableCardDAV := flag.Bool("disable-carddav", false, "Disable CardDAV for hydroxide serve")

	tlsCert := flag.String("tls-cert", "", "Path to the certificate to use for incoming connections")
	tlsCertKey := flag.String("tls-key", "", "Path to the certificate key to use for incoming connections")
	tlsClientCA := flag.String("tls-client-ca", "", "If set, clients must provide a certificate signed by the given CA")

	authCmd := flag.NewFlagSet("auth", flag.ExitOnError)
	authExportCmd := flag.NewFlagSet("auth-export", flag.ExitOnError)
	authExportIncludePasswords := authExportCmd.Bool("include-passwords", false, "Include cached Proton passwords in exported auth JSON")
	authImportCmd := flag.NewFlagSet("auth-import", flag.ExitOnError)
	authImportKeepPasswordReauth := authImportCmd.Bool("allow-password-reauth", false, "Keep automatic password re-auth enabled for imported auth state")
	authImportBridgePassword := authImportCmd.String("bridge-password", "", "Bridge password to use for the imported auth state (generated automatically when omitted)")
	authImportSkipVerify := authImportCmd.Bool("skip-verify", false, "Skip live refresh/unlock verification before saving imported auth state")
	authVerifyCmd := flag.NewFlagSet("auth-verify", flag.ExitOnError)
	exportSecretKeysCmd := flag.NewFlagSet("export-secret-keys", flag.ExitOnError)
	importMessagesCmd := flag.NewFlagSet("import-messages", flag.ExitOnError)
	exportMessagesCmd := flag.NewFlagSet("export-messages", flag.ExitOnError)
	sendmailCmd := flag.NewFlagSet("sendmail", flag.ExitOnError)

	flag.Usage = func() {
		fmt.Print(usage)
	}

	flag.Parse()

	tlsConfig, err := config.TLS(*tlsCert, *tlsCertKey, *tlsClientCA)
	if err != nil {
		log.Fatal(err)
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "auth":
		authCmd.Parse(flag.Args()[1:])
		username := authCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: hydroxide auth <username>")
		}

		c := newClient()

		var a *protonmail.Auth
		/*if cachedAuth, ok := auths[username]; ok {
			var err error
			a, err = c.AuthRefresh(a)
			if err != nil {
				// TODO: handle expired token error
				log.Fatal(err)
			}
		}*/

		var loginPassword string
		if a == nil {
			if pass, err := askPass("Password"); err != nil {
				log.Fatal(err)
			} else {
				loginPassword = string(pass)
			}

			authInfo, err := c.AuthInfo(username)
			if err != nil {
				log.Fatal(err)
			}

			a, err = c.Auth(username, loginPassword, authInfo)
			if err != nil {
				if apiErr, ok := err.(*protonmail.APIError); ok && apiErr.IsHVError() {
					a, err = completeHumanVerification(c, username, loginPassword, apiErr)
				}
				if err != nil {
					log.Fatal(err)
				}
			}

			if a.TwoFactor.Enabled != 0 {
				if a.TwoFactor.TOTP != 1 {
					log.Fatal("Only TOTP is supported as a 2FA method")
				}

				scanner := bufio.NewScanner(os.Stdin)
				fmt.Printf("2FA TOTP code: ")
				scanner.Scan()
				code := scanner.Text()

				scope, err := c.AuthTOTP(code)
				if err != nil {
					log.Fatal(err)
				}
				a.Scope = scope
			}
		}

		var mailboxPassword string
		if a.PasswordMode == protonmail.PasswordSingle {
			mailboxPassword = loginPassword
		}
		if mailboxPassword == "" {
			prompt := "Password"
			if a.PasswordMode == protonmail.PasswordTwo {
				prompt = "Mailbox password"
			}
			if pass, err := askPass(prompt); err != nil {
				log.Fatal(err)
			} else {
				mailboxPassword = string(pass)
			}
		}

		keySalts, err := c.ListKeySalts()
		if err != nil {
			log.Fatal(err)
		}

		_, err = c.Unlock(a, keySalts, mailboxPassword)
		if err != nil {
			log.Fatal(err)
		}

		secretKey, bridgePassword, err := auth.GeneratePassword()
		if err != nil {
			log.Fatal(err)
		}

		err = auth.EncryptAndSave(&auth.CachedAuth{
			Auth:                  *a,
			LoginPassword:         loginPassword,
			MailboxPassword:       mailboxPassword,
			KeySalts:              keySalts,
			DisablePasswordReauth: false,
		}, username, secretKey)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Bridge password:", bridgePassword)
	case "auth-export":
		authExportCmd.Parse(flag.Args()[1:])
		username := authExportCmd.Arg(0)
		exportPath := authExportCmd.Arg(1)
		if username == "" {
			log.Fatal("usage: hydroxide auth-export <username> [file]")
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		exported, err := auth.ExportCachedAuth(username, bridgePassword, *authExportIncludePasswords)
		if err != nil {
			log.Fatal(err)
		}

		data, err := json.MarshalIndent(exported, "", "  ")
		if err != nil {
			log.Fatal(err)
		}

		if exportPath == "" {
			os.Stdout.Write(data)
			os.Stdout.Write([]byte("\n"))
		} else if err := os.WriteFile(exportPath, append(data, '\n'), 0600); err != nil {
			log.Fatal(err)
		}
	case "auth-import":
		authImportCmd.Parse(flag.Args()[1:])
		username := authImportCmd.Arg(0)
		importPath := authImportCmd.Arg(1)
		if username == "" {
			log.Fatal("usage: hydroxide auth-import <username> [file]")
		}

		var r io.Reader = os.Stdin
		if importPath != "" {
			f, err := os.Open(importPath)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
			r = f
		}

		var imported auth.CachedAuth
		if err := json.NewDecoder(r).Decode(&imported); err != nil {
			log.Fatal(err)
		}

		imported.DisablePasswordReauth = !*authImportKeepPasswordReauth
		if imported.DisablePasswordReauth {
			imported.LoginPassword = ""
		}

		if !*authImportSkipVerify {
			c := newClient()
			refreshed, err := c.AuthRefresh(&imported.Auth)
			if err != nil {
				log.Fatalf("imported auth failed refresh verification: %v", err)
			}
			imported.Auth = *refreshed
			if _, err := c.Unlock(&imported.Auth, imported.KeySalts, imported.MailboxPassword); err != nil {
				log.Fatalf("imported auth failed mailbox unlock verification: %v", err)
			}
		}

		var (
			secretKey      *[32]byte
			bridgePassword string
		)
		if *authImportBridgePassword != "" {
			bridgePassword = *authImportBridgePassword
			secretKey, err = auth.DecodeBridgePassword(bridgePassword)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			secretKey, bridgePassword, err = auth.GeneratePassword()
			if err != nil {
				log.Fatal(err)
			}
		}

		if err := auth.ImportCachedAuth(username, &imported, secretKey); err != nil {
			log.Fatal(err)
		}

		fmt.Println("Bridge password:", bridgePassword)
		if imported.DisablePasswordReauth {
			fmt.Println("Mode: refresh-only (automatic password re-auth disabled)")
		} else {
			fmt.Println("Mode: password re-auth allowed")
		}
	case "auth-verify":
		authVerifyCmd.Parse(flag.Args()[1:])
		username := authVerifyCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: hydroxide auth-verify <username>")
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		cachedAuth, err := auth.Verify(newClient, username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Auth state verified successfully")
		fmt.Println("Refresh token present:", cachedAuth.RefreshToken != "")
		fmt.Println("Automatic password re-auth disabled:", cachedAuth.DisablePasswordReauth)
	case "status":
		usernames, err := auth.ListUsernames()
		if err != nil {
			log.Fatal(err)
		}

		if len(usernames) == 0 {
			fmt.Printf("No logged in user.\n")
		} else {
			fmt.Printf("%v logged in user(s):\n", len(usernames))
			for _, u := range usernames {
				fmt.Printf("- %v\n", u)
			}
		}
	case "export-secret-keys":
		exportSecretKeysCmd.Parse(flag.Args()[1:])
		username := exportSecretKeysCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: hydroxide export-secret-keys <username>")
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		_, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		wc, err := armor.Encode(os.Stdout, openpgp.PrivateKeyType, nil)
		if err != nil {
			log.Fatal(err)
		}

		for _, key := range privateKeys {
			if err := key.SerializePrivate(wc, nil); err != nil {
				log.Fatal(err)
			}
		}

		if err := wc.Close(); err != nil {
			log.Fatal(err)
		}
	case "import-messages":
		importMessagesCmd.Parse(flag.Args()[1:])
		username := importMessagesCmd.Arg(0)
		archivePath := importMessagesCmd.Arg(1)
		if username == "" {
			log.Fatal("usage: hydroxide import-messages <username> [file]")
		}

		f := os.Stdin
		if archivePath != "" {
			f, err = os.Open(archivePath)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		c, _, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		br := bufio.NewReader(f)
		if ok, err := isMbox(br); err != nil {
			log.Fatal(err)
		} else if ok {
			mr := mbox.NewReader(br)
			for {
				r, err := mr.NextMessage()
				if err == io.EOF {
					break
				} else if err != nil {
					log.Fatal(err)
				}
				if err := imports.ImportMessage(c, r); err != nil {
					log.Fatal(err)
				}
			}
		} else {
			if err := imports.ImportMessage(c, br); err != nil {
				log.Fatal(err)
			}
		}
	case "export-messages":
		// TODO: allow specifying multiple IDs
		var convID, msgID string
		exportMessagesCmd.StringVar(&convID, "conversation-id", "", "conversation ID")
		exportMessagesCmd.StringVar(&msgID, "message-id", "", "message ID")
		exportMessagesCmd.Parse(flag.Args()[1:])
		username := exportMessagesCmd.Arg(0)
		if (convID == "" && msgID == "") || username == "" {
			log.Fatal("usage: hydroxide export-messages [-conversation-id <id>] [-message-id <id>] <username>")
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		c, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		mboxWriter := mbox.NewWriter(os.Stdout)

		if convID != "" {
			if err := exports.ExportConversationMbox(c, privateKeys, mboxWriter, convID); err != nil {
				log.Fatal(err)
			}
		}
		if msgID != "" {
			if err := exports.ExportMessageMbox(c, privateKeys, mboxWriter, msgID); err != nil {
				log.Fatal(err)
			}
		}

		if err := mboxWriter.Close(); err != nil {
			log.Fatal(err)
		}
	case "smtp":
		addr := *smtpHost + ":" + *smtpPort
		authManager := auth.NewManager(newClient)
		log.Fatal(listenAndServeSMTP(addr, debug, authManager, tlsConfig))
	case "imap":
		addr := *imapHost + ":" + *imapPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeIMAP(addr, debug, authManager, eventsManager, tlsConfig))
	case "carddav":
		addr := *carddavHost + ":" + *carddavPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeCardDAV(addr, authManager, eventsManager, tlsConfig))
	case "serve":
		smtpAddr := *smtpHost + ":" + *smtpPort
		imapAddr := *imapHost + ":" + *imapPort
		carddavAddr := *carddavHost + ":" + *carddavPort

		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		go runBridgeRecoveryWatchdog()

		done := make(chan error, 3)
		if !*disableSMTP {
			go func() {
				done <- listenAndServeSMTP(smtpAddr, debug, authManager, tlsConfig)
			}()
		}
		if !*disableIMAP {
			go func() {
				done <- listenAndServeIMAP(imapAddr, debug, authManager, eventsManager, tlsConfig)
			}()
		}
		if !*disableCardDAV {
			go func() {
				done <- listenAndServeCardDAV(carddavAddr, authManager, eventsManager, tlsConfig)
			}()
		}
		log.Fatal(<-done)
	case "sendmail":
		username := flag.Arg(1)
		if username == "" || flag.Arg(2) != "--" {
			log.Fatal("usage: hydroxide sendmail <username> -- <args...>")
		}

		// TODO: other sendmail flags
		var dotEOF bool
		sendmailCmd.BoolVar(&dotEOF, "i", false, "don't treat a line with only a . character as the end of input")
		sendmailCmd.Parse(flag.Args()[3:])
		rcpt := sendmailCmd.Args()

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		c, privateKeys, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		u, err := c.GetCurrentUser()
		if err != nil {
			log.Fatal(err)
		}

		addrs, err := c.ListAddresses()
		if err != nil {
			log.Fatal(err)
		}

		err = smtpbackend.SendMail(c, u, privateKeys, addrs, rcpt, os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Print(usage)
		if cmd != "help" {
			log.Fatal("Unrecognized command")
		}
	}
}
