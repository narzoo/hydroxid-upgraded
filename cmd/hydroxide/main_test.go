package main

import (
	"context"
	"testing"
	"time"

	"github.com/emersion/hydroxide/protonmail"
)

func TestBridgeHealthMonitorRestartsOnlyAfterSustainedRecoverableFailures(t *testing.T) {
	monitor := &bridgeHealthMonitor{}

	for range bridgeRecoveryFailureThreshold {
		monitor.observe(context.DeadlineExceeded)
	}
	monitor.mu.Lock()
	monitor.firstFailureAt = time.Now().Add(-bridgeRecoveryMinimumAge)
	monitor.mu.Unlock()

	failures, _, restart := monitor.shouldRestart(time.Now())
	if !restart || failures != bridgeRecoveryFailureThreshold {
		t.Fatalf("expected a restart after sustained failures, got failures=%d restart=%v", failures, restart)
	}

	monitor.observe(nil)
	if _, _, restart := monitor.shouldRestart(time.Now()); restart {
		t.Fatal("a successful API response must cancel pending self-recovery")
	}
}

func TestRecoverableBridgeErrors(t *testing.T) {
	if !isRecoverableBridgeError(&protonmail.APIError{Code: 500}) {
		t.Fatal("expected API 500 to be recoverable")
	}
	if isRecoverableBridgeError(&protonmail.APIError{Code: 10013}) {
		t.Fatal("an invalid refresh token must not restart the whole bridge")
	}
}
