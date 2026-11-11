package appauth

import (
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

func issueListedEmailLink(t *testing.T, e *emailAuthenticator, start time.Time, email string, at time.Duration) bool {
	t.Helper()
	if e.issue(email, true, emailTestHost, "/", start.Add(at)) == "" {
		return false
	}
	<-e.sendSlots
	return true
}
func issueUnlistedEmailLink(t *testing.T, e *emailAuthenticator, start time.Time, email string, at time.Duration) bool {
	t.Helper()
	if e.issue(email, false, emailTestHost, "/", start.Add(at)) == "" {
		return false
	}
	<-e.sendSlots
	return true
}
func checkAddressSendLimits(t *testing.T) {
	t.Helper()
	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"})
	start := time.Now().UTC()
	if !issueListedEmailLink(t, e, start, "alice@example.com", 0) {
		t.Fatal("the first link was refused")
	}
	if issueListedEmailLink(t, e, start, "alice@example.com", emailAddressCooldown-time.Second) {
		t.Fatal("a second link within the cooldown was sent")
	}
	for i := 1; i < emailAddressHourlyLimit; i++ {
		if !issueListedEmailLink(t, e, start, "alice@example.com", time.Duration(i)*emailAddressCooldown) {
			t.Fatalf("link %d of the hour was refused", i+1)
		}
	}
	if issueListedEmailLink(t, e, start, "alice@example.com", emailAddressHourlyLimit*emailAddressCooldown) {
		t.Fatal("a link over the hourly limit of one address was sent")
	}
	if !issueListedEmailLink(t, e, start, "alice@example.com", time.Hour+time.Second) {
		t.Fatal("a link an hour after the first was refused")
	}
}
func checkDomainSendLimits(t *testing.T) {
	t.Helper()
	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"})
	start := time.Now().UTC()
	for i := range emailDomainHourlyLimit {
		if !issueUnlistedEmailLink(t, e, start, fmt.Sprintf("user%d@team.example", i), time.Duration(i)*time.Second) {
			t.Fatalf("domain link %d was refused", i+1)
		}
	}
	if issueUnlistedEmailLink(t, e, start, "late@team.example", time.Minute) {
		t.Fatal("a domain link over the hourly domain limit was sent")
	}
	if !issueListedEmailLink(t, e, start, "alice@example.com", time.Minute) {
		t.Fatal("a flood of domain addresses locked out an exactly listed address")
	}
	if !issueUnlistedEmailLink(t, e, start, "late@team.example", time.Hour+time.Second) {
		t.Fatal("a domain link after the hour was refused")
	}
}
func TestEmailSendLimits(t *testing.T) {
	t.Parallel()
	checkAddressSendLimits(t)
	checkDomainSendLimits(t)
}

func TestEmailSendDroppedForBusySlotsSpendsNoLimit(t *testing.T) {
	t.Parallel()

	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"})
	for range emailSendSlots {
		e.sendSlots <- struct{}{}
	}
	now := time.Now().UTC()
	e.send("alice@example.com", true, emailTestHost, "/", now)
	e.mu.Lock()
	links, sent := len(e.links), len(e.sent)
	e.mu.Unlock()
	if links != 0 || sent != 0 {
		t.Fatalf("a dropped send left %d links and %d recorded sends", links, sent)
	}
	for range emailSendSlots {
		<-e.sendSlots
	}
	if e.issue("alice@example.com", true, emailTestHost, "/", now) == "" {
		t.Fatal("the dropped send spent the cooldown of the address")
	}
}

func TestEmailRefusedSendsLeaveTheSlotsFree(t *testing.T) {
	t.Parallel()

	e := newEmailAuthenticator(applicationAuthSettings{emailSMTPAddr: "127.0.0.1:25"})
	now := time.Now().UTC()
	if e.issue("alice@example.com", true, emailTestHost, "/", now) == "" {
		t.Fatal("the first link was refused")
	}
	<-e.sendSlots
	for range emailSendSlots + 1 {
		if e.issue("alice@example.com", true, emailTestHost, "/", now) != "" {
			t.Fatal("the cooldown let a send through")
		}
	}
	if e.issue("bob@example.com", true, emailTestHost, "/", now) == "" {
		t.Fatal("refused sends took the slot of a real one")
	}
}

func TestEmailDomainBudgetSparesAListedAddress(t *testing.T) {
	t.Parallel()

	server := newSMTPTestServer(t, emailTestUsername, emailTestPassword)
	gate := newEmailTestGate(t, emailTestConfig(server.addr, "alice@team.example", "@team.example"), http.NotFoundHandler())
	now := time.Now().UTC()
	gate.email.mu.Lock()
	for i := range emailDomainHourlyLimit {
		gate.email.sent = append(gate.email.sent, emailSend{email: fmt.Sprintf("user%d@team.example", i), at: now})
	}
	gate.email.mu.Unlock()

	postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: "late@team.example"})
	server.expectNoMore(t)
	postEmailJSON(gate, emailTestHost, types.PathApplicationAuthEmailRequest, applicationAuthEmailRequest{Email: "alice@team.example"})
	if message := server.next(t); !slices.Equal(message.to, []string{"alice@team.example"}) {
		t.Fatalf("mail to %v", message.to)
	}
}
