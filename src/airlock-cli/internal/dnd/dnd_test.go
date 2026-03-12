package dnd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEvaluateForAction_NoPoliciesReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policy/dnd/effective" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"body": []interface{}{},
		})
	}))
	defer srv.Close()

	res, err := EvaluateForAction(srv.URL, "", "enf-1", "ws-1", "", Action{
		ActionType:  "terminal_command",
		CommandText: "git status",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Fatalf("expected nil result, got %+v", res)
	}
}

func TestEvaluateForAction_WorkspaceApproveAndDenyPrecedence(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-1 * time.Minute).Format(time.RFC3339)
	cur := now.Add(1 * time.Minute).Format(time.RFC3339)

	body := []policyWire{
		{
			RequestID:  "deny",
			ObjectType: "airlock.dnd.workspace",
			WorkspaceID: "ws-1",
			EnforcerID: "enf-1",
			PolicyMode: string(DecisionDenyAll),
			ExpiresAt:  cur,
			CreatedAt:  old,
		},
		{
			RequestID:  "approve",
			ObjectType: "airlock.dnd.workspace",
			WorkspaceID: "ws-1",
			EnforcerID: "enf-1",
			PolicyMode: string(DecisionApproveAll),
			ExpiresAt:  cur,
			CreatedAt:  cur,
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"body": body,
		})
	}))
	defer srv.Close()

	res, err := EvaluateForAction(srv.URL, "", "enf-1", "ws-1", "", Action{
		ActionType:  "terminal_command",
		CommandText: "git push",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatalf("expected match, got nil")
	}
	if res.Decision != "reject" {
		t.Fatalf("expected reject from deny_all, got %s", res.Decision)
	}
	if res.PolicyID != "deny" {
		t.Fatalf("expected policyId=deny, got %s", res.PolicyID)
	}
}

func TestEvaluateForAction_ActionPrefixMatchingAndPrecedence(t *testing.T) {
	now := time.Now().UTC().Add(1 * time.Minute).Format(time.RFC3339)

	body := []policyWire{
		{
			RequestID:  "broad",
			ObjectType: "airlock.dnd.action",
			WorkspaceID: "ws-1",
			EnforcerID: "enf-1",
			PolicyMode: string(DecisionApproveAll),
			ActionSelector: &actionSelector{
				ArgvPrefix: []string{"git"},
			},
			ExpiresAt: now,
			CreatedAt: now,
		},
		{
			RequestID:  "specific",
			ObjectType: "airlock.dnd.action",
			WorkspaceID: "ws-1",
			EnforcerID: "enf-1",
			PolicyMode: string(DecisionApproveAll),
			ActionSelector: &actionSelector{
				ArgvPrefix: []string{"git", "push"},
			},
			ExpiresAt: now,
			CreatedAt: now,
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"body": body,
		})
	}))
	defer srv.Close()

	res, err := EvaluateForAction(srv.URL, "", "enf-1", "ws-1", "", Action{
		ActionType:  "terminal_command",
		CommandText: "git push origin main",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatalf("expected match, got nil")
	}
	if res.Decision != "approve" {
		t.Fatalf("expected approve, got %s", res.Decision)
	}
	if res.PolicyID != "specific" {
		t.Fatalf("expected policyId=specific for longest prefix, got %s", res.PolicyID)
	}
}

func TestEvaluateForAction_IgnoresExpiredPolicies(t *testing.T) {
	expired := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)

	body := []policyWire{
		{
			RequestID:  "expired",
			ObjectType: "airlock.dnd.workspace",
			WorkspaceID: "ws-1",
			EnforcerID: "enf-1",
			PolicyMode: string(DecisionApproveAll),
			ExpiresAt:  expired,
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"body": body,
		})
	}))
	defer srv.Close()

	res, err := EvaluateForAction(srv.URL, "", "enf-1", "ws-1", "", Action{
		ActionType:  "terminal_command",
		CommandText: "git status",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Fatalf("expected nil due to expired policy, got %+v", res)
	}
}

