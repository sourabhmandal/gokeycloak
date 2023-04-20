package gokeycloak

type ClientInitialAccessTokenResponse struct {
	ID             string `json:"id"`
	Token          string `json:"token"`
	Timestamp      int    `json:"timestamp"`
	Expiration     int    `json:"expiration"`
	Count          int    `json:"count"`
	RemainingCount int    `json:"remainingCount"`
}

type ClientInitialAccessTokenRequest struct {
	Count      int `json:"count,omitempty"`
	Expiration int `json:"expiration,omitempty"`
}

type CreateClientResponse struct {
	RedirectUris                          []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod               string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes                            []string `json:"grant_types,omitempty"`
	ResponseTypes                         []string `json:"response_types,omitempty"`
	ClientID                              string   `json:"client_id,omitempty"`
	ClientSecret                          string   `json:"client_secret,omitempty"`
	Scope                                 string   `json:"scope,omitempty"`
	SubjectType                           string   `json:"subject_type,omitempty"`
	RequestUris                           []any    `json:"request_uris,omitempty"`
	TLSClientCertificateBoundAccessTokens bool     `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	ClientIDIssuedAt                      int      `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt                 int      `json:"client_secret_expires_at,omitempty"`
	RegistrationClientURI                 string   `json:"registration_client_uri,omitempty"`
	RegistrationAccessToken               string   `json:"registration_access_token,omitempty"`
	BackchannelLogoutSessionRequired      bool     `json:"backchannel_logout_session_required,omitempty"`
	RequirePushedAuthorizationRequests    bool     `json:"require_pushed_authorization_requests,omitempty"`
	FrontchannelLogoutSessionRequired     bool     `json:"frontchannel_logout_session_required,omitempty"`
}