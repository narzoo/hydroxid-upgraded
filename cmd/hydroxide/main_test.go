package main

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/emersion/hydroxide/protonmail"
)

func TestBridgeHealthMonitorRestartsOnlyAfterSustainedRecoverableFailures(t *testing.T) {
	monitor := &bridgeHealthMonitor{}

	for range bridgeRecoveryFailureThreshold {
		monitor.observe(nil, context.DeadlineExceeded)
	}
	monitor.mu.Lock()
	monitor.firstFailureAt = time.Now().Add(-bridgeRecoveryMinimumAge)
	monitor.mu.Unlock()

	_, failures, _, restart := monitor.shouldRestart(time.Now())
	if !restart || failures != bridgeRecoveryFailureThreshold {
		t.Fatalf("expected a restart after sustained failures, got failures=%d restart=%v", failures, restart)
	}

	monitor.observe(nil, nil)
	if _, _, _, restart := monitor.shouldRestart(time.Now()); restart {
		t.Fatal("a successful API response must cancel pending self-recovery")
	}
}

func TestBridgeHealthMonitorRestartsStalledIMAPOperation(t *testing.T) {
	monitor := &bridgeHealthMonitor{}
	monitor.BeginIMAPOperation()
	monitor.mu.Lock()
	monitor.oldestIMAPOpAt = time.Now().Add(-imapOperationStallTimeout)
	monitor.mu.Unlock()

	reason, active, _, restart := monitor.shouldRestart(time.Now())
	if !restart || reason != "stalled IMAP operation" || active != 1 {
		t.Fatalf("expected stalled IMAP restart, got reason=%q active=%d restart=%v", reason, active, restart)
	}
}

func TestRecoverableBridgeErrors(t *testing.T) {
	eventRequest := &http.Request{URL: &url.URL{Path: "/api/events/latest"}}
	if !isRecoverableBridgeError(eventRequest, &protonmail.APIError{Code: 500}) {
		t.Fatal("expected API 500 to be recoverable")
	}
	if isRecoverableBridgeError(nil, &protonmail.APIError{Code: 10013}) {
		t.Fatal("an invalid refresh token must not restart the whole bridge")
	}
}
