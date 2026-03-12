package dnd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DecisionMode is the DND policy mode from the backend.
type DecisionMode string

const (
	DecisionApproveAll DecisionMode = "approve_all"
	DecisionDenyAll    DecisionMode = "deny_all"
)

// MatchResult is the outcome of evaluating DND policies for an action.
type MatchResult struct {
	Decision  string       // "approve" or "reject"
	PolicyID  string
	PolicyMode DecisionMode
	Scope     string // "workspace" or "action"
}

// Action describes the action we want to evaluate against DND rules.
type Action struct {
	ActionType  string
	CommandText string
}

type actionSelector struct {
	CommandFamily string   `json:"commandFamily,omitempty"`
	ArgvPrefix    []string `json:"argvPrefix,omitempty"`
}

type policyWire struct {
	RequestID         string         `json:"requestId"`
	ObjectType        string         `json:"objectType"`
	WorkspaceID       string         `json:"workspaceId"`
	SessionID         string         `json:"sessionId,omitempty"`
	EnforcerID        string         `json:"enforcerId"`
	PolicyMode        string         `json:"policyMode"`
	TargetArtifactType string        `json:"targetArtifactType,omitempty"`
	ActionSelector    *actionSelector `json:"actionSelector,omitempty"`
	SelectorHash      string         `json:"selectorHash,omitempty"`
	CreatedAt         string         `json:"createdAt,omitempty"`
	ExpiresAt         string         `json:"expiresAt"`
}

type policyEntry struct {
	Policy policyWire
	Scope  string // "workspace" or "action"
}

// EvaluateForAction fetches effective DND policies for the given enforcer/workspace/session
// and evaluates them against the provided action. Returns nil if no policy applies.
//
// This mirrors the precedence rules used by the IDE enforcers:
//   1) action-level deny
//   2) workspace-level deny
//   3) action-level approve
//   4) workspace-level approve
func EvaluateForAction(
	baseURL, token, enforcerID, workspaceID, sessionID string,
	action Action,
) (*MatchResult, error) {
	policies, err := getEffectivePolicies(baseURL, token, enforcerID, workspaceID, sessionID)
	if err != nil {
		return nil, err
	}
	if len(policies) == 0 {
		return nil, nil
	}

	now := time.Now()
	active := make([]policyEntry, 0, len(policies))
	for _, p := range policies {
		if p.Policy.ExpiresAt == "" {
			continue
		}
		exp, err := time.Parse(time.RFC3339, p.Policy.ExpiresAt)
		if err != nil {
			continue
		}
		if exp.After(now) {
			active = append(active, p)
		}
	}
	if len(active) == 0 {
		return nil, nil
	}

	wsDeny, wsApprove, actDeny, actApprove := classify(active)

	if m := findBestActionMatch(actDeny, action); m != nil {
		return toResult("reject", *m), nil
	}
	if m := pickNewest(wsDeny); m != nil {
		return toResult("reject", *m), nil
	}
	if m := findBestActionMatch(actApprove, action); m != nil {
		return toResult("approve", *m), nil
	}
	if m := pickNewest(wsApprove); m != nil {
		return toResult("approve", *m), nil
	}

	return nil, nil
}

func getEffectivePolicies(
	baseURL, token, enforcerID, workspaceID, sessionID string,
) ([]policyEntry, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/") + "/v1/policy/dnd/effective")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("enforcerId", enforcerID)
	q.Set("workspaceId", workspaceID)
	if sessionID != "" {
		q.Set("sessionId", sessionID)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dnd effective request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Treat any non-200 as "no policies" to avoid breaking approvals.
		return []policyEntry{}, nil
	}

	var envelope struct {
		Body []policyWire `json:"body"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode dnd effective response: %w", err)
	}

	entries := make([]policyEntry, 0, len(envelope.Body))
	for _, p := range envelope.Body {
		if p.RequestID == "" || p.ObjectType == "" || p.WorkspaceID == "" || p.EnforcerID == "" || p.PolicyMode == "" || p.ExpiresAt == "" {
			continue
		}
		scope := "workspace"
		if p.ObjectType == "airlock.dnd.action" {
			scope = "action"
		}
		entries = append(entries, policyEntry{
			Policy: p,
			Scope:  scope,
		})
	}
	return entries, nil
}

func classify(entries []policyEntry) (wsDeny, wsApprove, actDeny, actApprove []policyEntry) {
	for _, e := range entries {
		mode := strings.ToLower(e.Policy.PolicyMode)
		isDeny := mode == string(DecisionDenyAll)
		isApprove := mode == string(DecisionApproveAll)
		if !isDeny && !isApprove {
			continue
		}

		switch e.Scope {
		case "workspace":
			if isDeny {
				wsDeny = append(wsDeny, e)
			} else {
				wsApprove = append(wsApprove, e)
			}
		case "action":
			if isDeny {
				actDeny = append(actDeny, e)
			} else {
				actApprove = append(actApprove, e)
			}
		}
	}
	return
}

func findBestActionMatch(candidates []policyEntry, action Action) *policyEntry {
	if len(candidates) == 0 {
		return nil
	}
	argv := tokenize(action.CommandText)
	if len(argv) == 0 {
		return nil
	}

	var best *policyEntry
	bestPrefixLen := -1
	var bestCreatedAt time.Time

	for i := range candidates {
		e := &candidates[i]
		sel := e.Policy.ActionSelector
		if sel == nil || len(sel.ArgvPrefix) == 0 {
			continue
		}

		selectorTokens := make([]string, 0, len(sel.ArgvPrefix))
		for _, p := range sel.ArgvPrefix {
			for _, t := range strings.Fields(p) {
				if t != "" {
					selectorTokens = append(selectorTokens, t)
				}
			}
		}
		if len(selectorTokens) == 0 {
			continue
		}

		if !matchesPrefix(argv, selectorTokens) {
			continue
		}

		prefixLen := len(selectorTokens)
		createdAt := parseTime(e.Policy.CreatedAt)

		if prefixLen > bestPrefixLen || (prefixLen == bestPrefixLen && createdAt.After(bestCreatedAt)) {
			best = e
			bestPrefixLen = prefixLen
			bestCreatedAt = createdAt
		}
	}
	return best
}

func tokenize(cmd string) []string {
	fields := strings.Fields(cmd)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func matchesPrefix(argv, prefix []string) bool {
	if len(argv) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if argv[i] != prefix[i] {
			return false
		}
	}
	return true
}

func pickNewest(entries []policyEntry) *policyEntry {
	if len(entries) == 0 {
		return nil
	}
	best := &entries[0]
	bestCreatedAt := parseTime(best.Policy.CreatedAt)
	for i := 1; i < len(entries); i++ {
		c := &entries[i]
		createdAt := parseTime(c.Policy.CreatedAt)
		if createdAt.After(bestCreatedAt) {
			best = c
			bestCreatedAt = createdAt
		}
	}
	return best
}

func toResult(decision string, entry policyEntry) *MatchResult {
	return &MatchResult{
		Decision:  decision,
		PolicyID:  entry.Policy.RequestID,
		PolicyMode: DecisionMode(strings.ToLower(entry.Policy.PolicyMode)),
		Scope:     entry.Scope,
	}
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

