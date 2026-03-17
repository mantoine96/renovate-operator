package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const githubAPIBaseURL = "https://api.github.com"

type GitHubOAuthConfig struct {
	ClientID            string
	ClientSecret        string
	RedirectURL         string
	SessionSecret       string
	AllowedGroupPrefix  string
	AllowedGroupPattern string
}

type GitHubOAuth struct {
	baseAuth
	oauth2Config      oauth2.Config
	httpClient        *http.Client
	groupFilterConfig GroupFilterConfig
	apiBaseURL        string // defaults to githubAPIBaseURL, overridable for tests
}

func NewGitHubOAuth(cfg GitHubOAuthConfig, logger logr.Logger) (*GitHubOAuth, error) {
	oauth2Cfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     github.Endpoint,
		Scopes:       []string{"read:user", "user:email", "read:org"},
	}

	key, err := newEncryptionKey(cfg.SessionSecret)
	if err != nil {
		return nil, err
	}

	var groupFilterConfig GroupFilterConfig
	groupFilterConfig.AllowedPrefix = strings.ToLower(cfg.AllowedGroupPrefix)
	if cfg.AllowedGroupPattern != "" {
		pattern, err := regexp.Compile(cfg.AllowedGroupPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid group pattern regex: %w", err)
		}
		groupFilterConfig.AllowedPattern = pattern
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}

	return &GitHubOAuth{
		baseAuth:          baseAuth{encryptionKey: key, logger: logger},
		oauth2Config:      oauth2Cfg,
		httpClient:        httpClient,
		groupFilterConfig: groupFilterConfig,
		apiBaseURL:        githubAPIBaseURL,
	}, nil
}

func (g *GitHubOAuth) AuthMiddleware(next http.Handler) http.Handler {
	return g.authMiddleware(next)
}

func (g *GitHubOAuth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	g.logger.Info("login initiated", "remoteAddr", r.RemoteAddr)
	state, err := g.setStateCookie(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	authURL := g.oauth2Config.AuthCodeURL(state)
	g.logger.Info("redirecting to GitHub", "url", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (g *GitHubOAuth) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Prevent proxies from caching this response (it contains Set-Cookie headers)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")

	g.logger.Info("callback received", "hasCode", r.URL.Query().Get("code") != "", "hasState", r.URL.Query().Get("state") != "")

	if err := g.validateStateCookie(r); err != nil {
		g.logger.Error(err, "state cookie validation failed")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	g.clearStateCookie(w)

	oauth2Token, err := g.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		g.logger.Error(err, "failed to exchange code for token")
		http.Error(w, "failed to exchange token", http.StatusInternalServerError)
		return
	}
	g.logger.Info("token exchange successful")

	// Fetch user info from GitHub API
	email, name, err := g.fetchGitHubUser(oauth2Token.AccessToken)
	if err != nil {
		g.logger.Error(err, "failed to fetch GitHub user info")
		http.Error(w, "failed to fetch user info", http.StatusInternalServerError)
		return
	}
	g.logger.Info("user info fetched", "email", email, "name", name)

	// Fetch team memberships from GitHub API
	teams, err := g.fetchUserTeams(r.Context(), oauth2Token.AccessToken)
	if err != nil {
		g.logger.Error(err, "failed to fetch GitHub team memberships")
		// When group filtering is configured, team fetch failure is fatal
		// to prevent silent access degradation
		if g.groupFilterConfig.AllowedPrefix != "" || g.groupFilterConfig.AllowedPattern != nil {
			http.Error(w, "failed to verify team membership", http.StatusInternalServerError)
			return
		}
		// Without group filtering, proceed without groups rather than blocking login
		teams = nil
	}

	// Apply 3-layer group validation
	validatedGroups := ValidateAndNormalizeGroups(teams, g.groupFilterConfig, g.logger)

	g.logger.V(1).Info("GitHub teams received",
		"user", email,
		"teams", teams,
		"validated_groups", validatedGroups)

	if len(teams) > 0 && len(validatedGroups) == 0 {
		g.logger.Info("WARNING: User authenticated but all groups filtered out",
			"user", email,
			"original_teams", teams)
	}

	// Redirect to /auth/complete with the encrypted session token.
	// The cookie is set there, not here, because some reverse proxies strip
	// Set-Cookie headers from OAuth callback responses.
	completeURL, err := g.buildCompleteURL(email, name, func(s *sessionData) {
		s.AccessToken = oauth2Token.AccessToken
		s.Groups = validatedGroups
	})
	if err != nil {
		g.logger.Error(err, "failed to build complete URL")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, completeURL, http.StatusFound)
}

func (g *GitHubOAuth) HandleComplete(w http.ResponseWriter, r *http.Request) {
	g.handleComplete(w, r)
}

func (g *GitHubOAuth) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if session, err := g.getSession(r); err == nil && session.AccessToken != "" {
		g.revokeGitHubToken(session.AccessToken)
	}
	g.clearSessionCookie(w)
	http.Redirect(w, r, "/auth/logged-out", http.StatusFound)
}

func (g *GitHubOAuth) revokeGitHubToken(accessToken string) {
	url := fmt.Sprintf("https://api.github.com/applications/%s/token", g.oauth2Config.ClientID)
	body := fmt.Sprintf(`{"access_token":"%s"}`, accessToken)
	req, err := http.NewRequest("DELETE", url, strings.NewReader(body))
	if err != nil {
		g.logger.Error(err, "failed to create token revocation request")
		return
	}
	req.SetBasicAuth(g.oauth2Config.ClientID, g.oauth2Config.ClientSecret)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		g.logger.Error(err, "failed to revoke GitHub token")
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			g.logger.Error(err, "failed to close response body")
		}
	}()

	if resp.StatusCode == http.StatusNoContent {
		g.logger.Info("GitHub OAuth token revoked successfully")
	} else {
		g.logger.Info("GitHub token revocation returned unexpected status", "status", resp.StatusCode)
	}
}

func (g *GitHubOAuth) HandleAuthStatus(w http.ResponseWriter, r *http.Request) {
	g.handleAuthStatus(w, r)
}

func (g *GitHubOAuth) SupportsGroups() bool {
	return false
}

func (g *GitHubOAuth) fetchGitHubUser(accessToken string) (email, name string, err error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			g.logger.Error(err, "failed to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var user struct {
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", "", err
	}

	name = user.Name
	if name == "" {
		name = user.Login
	}
	email = user.Email
	if email == "" {
		// Email might be private, try the emails endpoint
		email, _ = g.fetchPrimaryEmail(accessToken)
	}
	if email == "" {
		email = user.Login + "@github"
	}

	return email, name, nil
}

func (g *GitHubOAuth) fetchPrimaryEmail(accessToken string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			g.logger.Error(err, "failed to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub emails API returned status %d", resp.StatusCode)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}

	return "", fmt.Errorf("no verified email found")
}

// githubTeamEntry represents a single team from the GitHub /user/teams API.
type githubTeamEntry struct {
	Slug string `json:"slug"`
	Org  struct {
		Login string `json:"login"`
	} `json:"organization"`
}

// fetchTeamPage fetches a single page of teams from the GitHub API.
// Returns the parsed teams, the next page URL (empty if none), and any error.
func (g *GitHubOAuth) fetchTeamPage(ctx context.Context, pageURL, accessToken string) ([]githubTeamEntry, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			g.logger.Error(err, "failed to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("GitHub teams API returned status %d", resp.StatusCode)
	}

	var page []githubTeamEntry
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, "", fmt.Errorf("failed to decode teams response: %w", err)
	}

	nextURL := parseNextLink(resp.Header.Get("Link"))
	return page, nextURL, nil
}

// fetchUserTeams calls the GitHub API to retrieve the authenticated user's
// team memberships. Each team is returned in "org-login/team-slug" format.
// Pagination is followed up to maxGroupsPerUser total teams.
func (g *GitHubOAuth) fetchUserTeams(ctx context.Context, accessToken string) ([]string, error) {
	var teams []string
	nextURL := g.apiBaseURL + "/user/teams?per_page=100"

	for nextURL != "" && len(teams) < maxGroupsPerUser {
		page, next, err := g.fetchTeamPage(ctx, nextURL, accessToken)
		if err != nil {
			return nil, err
		}

		for _, t := range page {
			if len(teams) >= maxGroupsPerUser {
				g.logger.Info("GitHub team count reached limit, truncating",
					"limit", maxGroupsPerUser)
				return teams, nil
			}
			teams = append(teams, t.Org.Login+"/"+t.Slug)
		}

		if next != "" && !validateNextURL(next, g.apiBaseURL) {
			g.logger.Info("Ignoring pagination URL with unexpected host",
				"url", next, "expected_host", g.apiBaseURL)
			break
		}
		nextURL = next
	}

	return teams, nil
}

// parseNextLink extracts the URL for rel="next" from a GitHub Link header.
// Returns empty string if no next page exists.
func parseNextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}
	for _, part := range strings.Split(linkHeader, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start >= 0 && end > start {
			return part[start+1 : end]
		}
	}
	return ""
}

// validateNextURL checks that a pagination URL points to the same host as
// the configured API base URL. This prevents SSRF via manipulated Link headers
// that could redirect requests (with the Bearer token) to an attacker-controlled server.
func validateNextURL(nextURL, apiBaseURL string) bool {
	parsed, err := url.Parse(nextURL)
	if err != nil {
		return false
	}
	expected, err := url.Parse(apiBaseURL)
	if err != nil {
		return false
	}
	return parsed.Host == expected.Host
}
