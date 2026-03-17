package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/go-logr/logr"
)

func TestFetchUserTeams(t *testing.T) {
	teams := []githubTeamEntry{
		{Slug: "backend", Org: struct {
			Login string `json:"login"`
		}{Login: "myorg"}},
		{Slug: "platform-team", Org: struct {
			Login string `json:"login"`
		}{Login: "myorg"}},
		{Slug: "oss-contrib", Org: struct {
			Login string `json:"login"`
		}{Login: "other-org"}},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected authorization header: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(teams)
	}))
	defer server.Close()

	g := &GitHubOAuth{
		baseAuth:   baseAuth{logger: logr.Discard()},
		httpClient: server.Client(),
		apiBaseURL: server.URL,
	}

	result, err := g.fetchUserTeams(context.Background(), "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"myorg/backend", "myorg/platform-team", "other-org/oss-contrib"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d teams, got %d: %v", len(expected), len(result), result)
	}
	for i, team := range result {
		if team != expected[i] {
			t.Errorf("team[%d] = %q, want %q", i, team, expected[i])
		}
	}
}

func TestFetchUserTeamsPagination(t *testing.T) {
	page1Teams := []githubTeamEntry{
		{Slug: "team-a", Org: struct {
			Login string `json:"login"`
		}{Login: "org1"}},
	}
	page2Teams := []githubTeamEntry{
		{Slug: "team-b", Org: struct {
			Login string `json:"login"`
		}{Login: "org2"}},
	}

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "2" {
			_ = json.NewEncoder(w).Encode(page2Teams)
			return
		}
		// First page: include Link header pointing to page 2
		w.Header().Set("Link", fmt.Sprintf(`<%s/user/teams?per_page=100&page=2>; rel="next"`, serverURL))
		_ = json.NewEncoder(w).Encode(page1Teams)
	}))
	defer server.Close()
	serverURL = server.URL

	g := &GitHubOAuth{
		baseAuth:   baseAuth{logger: logr.Discard()},
		httpClient: server.Client(),
		apiBaseURL: server.URL,
	}

	result, err := g.fetchUserTeams(context.Background(), "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"org1/team-a", "org2/team-b"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d teams, got %d: %v", len(expected), len(result), result)
	}
	for i, team := range result {
		if team != expected[i] {
			t.Errorf("team[%d] = %q, want %q", i, team, expected[i])
		}
	}
}

func TestFetchUserTeamsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	g := &GitHubOAuth{
		baseAuth:   baseAuth{logger: logr.Discard()},
		httpClient: server.Client(),
		apiBaseURL: server.URL,
	}

	_, err := g.fetchUserTeams(context.Background(), "test-token")
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if got := err.Error(); got != "GitHub teams API returned status 403" {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestFetchUserTeamsMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	g := &GitHubOAuth{
		baseAuth:   baseAuth{logger: logr.Discard()},
		httpClient: server.Client(),
		apiBaseURL: server.URL,
	}

	_, err := g.fetchUserTeams(context.Background(), "test-token")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestFetchUserTeamsMaxCap(t *testing.T) {
	var teams []githubTeamEntry
	for i := 0; i < maxGroupsPerUser+10; i++ {
		teams = append(teams, githubTeamEntry{
			Slug: fmt.Sprintf("team-%d", i),
			Org: struct {
				Login string `json:"login"`
			}{Login: "org"},
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(teams)
	}))
	defer server.Close()

	g := &GitHubOAuth{
		baseAuth:   baseAuth{logger: logr.Discard()},
		httpClient: server.Client(),
		apiBaseURL: server.URL,
	}

	result, err := g.fetchUserTeams(context.Background(), "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != maxGroupsPerUser {
		t.Errorf("expected %d teams (maxGroupsPerUser), got %d", maxGroupsPerUser, len(result))
	}
}

func TestFetchUserTeamsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]githubTeamEntry{})
	}))
	defer server.Close()

	g := &GitHubOAuth{
		baseAuth:   baseAuth{logger: logr.Discard()},
		httpClient: server.Client(),
		apiBaseURL: server.URL,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := g.fetchUserTeams(ctx, "test-token")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestFetchUserTeamsGroupValidationIntegration(t *testing.T) {
	rawTeams := []string{
		"MyOrg/Backend-Team",
		"myorg/backend-team", // duplicate after normalization
		"other-org/platform",
		"myorg/infra",
	}

	config := GroupFilterConfig{
		AllowedPrefix: "myorg/",
	}

	result := ValidateAndNormalizeGroups(rawTeams, config, logr.Discard())

	// After normalization: myorg/backend-team, myorg/backend-team (deduped), other-org/platform, myorg/infra
	// After prefix filter (myorg/): myorg/backend-team, myorg/infra
	expected := []string{"myorg/backend-team", "myorg/infra"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d groups, got %d: %v", len(expected), len(result), result)
	}
	for i, g := range result {
		if g != expected[i] {
			t.Errorf("group[%d] = %q, want %q", i, g, expected[i])
		}
	}
}

func TestFetchUserTeamsGroupPatternIntegration(t *testing.T) {
	rawTeams := []string{
		"myorg/team-alpha",
		"myorg/deploy-beta",
		"other/team-gamma",
	}

	config := GroupFilterConfig{
		AllowedPattern: regexp.MustCompile(`^myorg/team-`),
	}

	result := ValidateAndNormalizeGroups(rawTeams, config, logr.Discard())

	expected := []string{"myorg/team-alpha"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d groups, got %d: %v", len(expected), len(result), result)
	}
	if result[0] != expected[0] {
		t.Errorf("group[0] = %q, want %q", result[0], expected[0])
	}
}

func TestParseNextLink(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "with next link",
			header:   `<https://api.github.com/user/teams?per_page=100&page=2>; rel="next", <https://api.github.com/user/teams?per_page=100&page=5>; rel="last"`,
			expected: "https://api.github.com/user/teams?per_page=100&page=2",
		},
		{
			name:     "no next link",
			header:   `<https://api.github.com/user/teams?per_page=100&page=5>; rel="last"`,
			expected: "",
		},
		{
			name:     "empty header",
			header:   "",
			expected: "",
		},
		{
			name:     "next only",
			header:   `<https://api.github.com/user/teams?page=3>; rel="next"`,
			expected: "https://api.github.com/user/teams?page=3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseNextLink(tt.header)
			if result != tt.expected {
				t.Errorf("parseNextLink(%q) = %q, want %q", tt.header, result, tt.expected)
			}
		})
	}
}

func TestValidateNextURL(t *testing.T) {
	tests := []struct {
		name       string
		nextURL    string
		apiBaseURL string
		valid      bool
	}{
		{
			name:       "same host",
			nextURL:    "https://api.github.com/user/teams?page=2",
			apiBaseURL: "https://api.github.com",
			valid:      true,
		},
		{
			name:       "different host rejected",
			nextURL:    "https://evil.example.com/steal?token=x",
			apiBaseURL: "https://api.github.com",
			valid:      false,
		},
		{
			name:       "localhost test server",
			nextURL:    "http://127.0.0.1:12345/user/teams?page=2",
			apiBaseURL: "http://127.0.0.1:12345",
			valid:      true,
		},
		{
			name:       "internal SSRF attempt",
			nextURL:    "http://169.254.169.254/latest/meta-data/",
			apiBaseURL: "https://api.github.com",
			valid:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateNextURL(tt.nextURL, tt.apiBaseURL)
			if result != tt.valid {
				t.Errorf("validateNextURL(%q, %q) = %v, want %v", tt.nextURL, tt.apiBaseURL, result, tt.valid)
			}
		})
	}
}
