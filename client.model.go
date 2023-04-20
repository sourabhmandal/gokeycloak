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

type ClientInitialAccessTokenOptions func(f *ClientInitialAccessTokenRequest)