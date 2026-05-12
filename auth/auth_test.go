package auth

import (
	"runtime"
	"testing"

	"github.com/emersion/hydroxide/protonmail"
)

func setTestConfigHome(t *testing.T) {
	t.Helper()

	tmpDir := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", tmpDir)
	} else {
		t.Setenv("XDG_CONFIG_HOME", tmpDir)
		t.Setenv("HOME", tmpDir)
	}
}

func TestExportCachedAuthStripsLoginPasswordOnly(t *testing.T) {
	setTestConfigHome(t)

	secretKey, bridgePassword, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}

	input := &CachedAuth{
		Auth: protonmail.Auth{
			UID:          "uid-1",
			RefreshToken: "refresh-1",
		},
		LoginPassword:         "login-secret",
		MailboxPassword:       "mailbox-secret",
		DisablePasswordReauth: false,
	}

	if err := EncryptAndSave(input, "alice@proton.me", secretKey); err != nil {
		t.Fatalf("EncryptAndSave() error = %v", err)
	}

	exported, err := ExportCachedAuth("alice@proton.me", bridgePassword, false)
	if err != nil {
		t.Fatalf("ExportCachedAuth() error = %v", err)
	}

	if exported.LoginPassword != "" {
		t.Fatalf("expected login password to be stripped, got %q", exported.LoginPassword)
	}
	if exported.MailboxPassword != "mailbox-secret" {
		t.Fatalf("expected mailbox password to be preserved, got %q", exported.MailboxPassword)
	}
	if !exported.DisablePasswordReauth {
		t.Fatal("expected exported auth to disable automatic password re-auth")
	}
	if exported.RefreshToken != "refresh-1" || exported.UID != "uid-1" {
		t.Fatal("expected export to preserve UID and refresh token")
	}
}

func TestImportCachedAuthRoundTrip(t *testing.T) {
	setTestConfigHome(t)

	secretKey, bridgePassword, err := GeneratePassword()
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}

	input := &CachedAuth{
		Auth: protonmail.Auth{
			UID:          "uid-2",
			RefreshToken: "refresh-2",
		},
		MailboxPassword:       "mailbox-secret",
		KeySalts:              map[string][]byte{"key-1": []byte("salt-1")},
		DisablePasswordReauth: true,
	}

	if err := ImportCachedAuth("bob@proton.me", input, secretKey); err != nil {
		t.Fatalf("ImportCachedAuth() error = %v", err)
	}

	loaded, _, err := LoadCachedAuth("bob@proton.me", bridgePassword)
	if err != nil {
		t.Fatalf("LoadCachedAuth() error = %v", err)
	}

	if loaded.UID != input.UID || loaded.RefreshToken != input.RefreshToken {
		t.Fatal("expected imported auth to preserve UID and refresh token")
	}
	if loaded.MailboxPassword != input.MailboxPassword {
		t.Fatalf("expected mailbox password %q, got %q", input.MailboxPassword, loaded.MailboxPassword)
	}
	if !loaded.DisablePasswordReauth {
		t.Fatal("expected imported auth to preserve DisablePasswordReauth")
	}
	if got := string(loaded.KeySalts["key-1"]); got != "salt-1" {
		t.Fatalf("expected key salt to round-trip, got %q", got)
	}
}
