package gocloak

import (
	"context"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
)

// SetOpenIDConnectEndpoint sets the logout
func SetOpenIDConnectEndpoint(url string) func(g *GoCloak) {
	return func(g *GoCloak) {
		g.Config.openIDConnect = url
	}
}

// // SetRevokeEndpoint sets the revoke endpoint
// func (g *GoCloak) GetRevokeEndpoint() string {
// 	return g.Config.openIDConnect + "revoke"
// }

// // SetLogoutEndpoint sets the logout
// func (g *GoCloak) GetLogoutEndpoint() string {
// 	return g.Config.openIDConnect + "logout"
// }

//----------------------------------------------------------------------------------
//													REALM CERTIFICATES
//----------------------------------------------------------------------------------

// GetCerts fetches certificates for the given realm from the public /open-id-connect/certs endpoint
func (g *GoCloak) GetCerts(ctx context.Context, realm string) (*CertResponse, error) {
	const errMessage = "could not get certs"

	if cert, ok := g.certsCache.Load(realm); ok {
		return cert.(*CertResponse), nil
	}

	g.certsLock.Lock()
	defer g.certsLock.Unlock()

	if cert, ok := g.certsCache.Load(realm); ok {
		return cert.(*CertResponse), nil
	}

	cert, err := g.getNewCerts(ctx, realm)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	g.certsCache.Store(realm, cert)
	time.AfterFunc(g.Config.CertsInvalidateTime, func() {
		g.certsCache.Delete(realm)
	})

	return cert, nil
}

func (g *GoCloak) getNewCerts(ctx context.Context, realm string) (*CertResponse, error) {
	const errMessage = "could not get newCerts"

	var result CertResponse
	resp, err := g.GetRequest(ctx).
		SetResult(&result).
		Get(g.getRealmURL(realm, g.Config.openIDConnect, "certs"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

//----------------------------------------------------------------------------------
//																USERINFO
//----------------------------------------------------------------------------------

// GetUserInfo calls the UserInfo endpoint
func (g *GoCloak) GetUserInfo(ctx context.Context, accessToken, realm string) (*UserInfo, error) {
	const errMessage = "could not get user info"

	var result UserInfo
	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(g.getRealmURL(realm, g.Config.openIDConnect, "userinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRawUserInfo calls the UserInfo endpoint and returns a raw json object
func (g *GoCloak) GetRawUserInfo(ctx context.Context, accessToken, realm string) (map[string]interface{}, error) {
	const errMessage = "could not get user info"

	var result map[string]interface{}
	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(g.getRealmURL(realm, g.Config.openIDConnect, "userinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

//----------------------------------------------------------------------------------
//																TOKEN
//----------------------------------------------------------------------------------
// RetrospectToken calls the openid-connect introspect endpoint
func (g *GoCloak) IntrospectToken(ctx context.Context, accessToken, clientID, clientSecret, realm string) (*IntroSpectTokenResult, error) {
	const errMessage = "could not introspect requesting party token"

	var result IntroSpectTokenResult
	resp, err := g.GetRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"token_type_hint": "requesting_party_token",
			"token":           accessToken,
		}).
		SetResult(&result).
		Post(g.getRealmURL(realm, g.Config.openIDConnect, "token", "introspect"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// URL: {{keycloak_url}}/realms/{{realm}}/protocol/openid-connect/token
// GetToken uses TokenOptions to fetch a token.
func (g *GoCloak) GetToken(ctx context.Context, realm string, options TokenOptions) (*JWT, error) {
	const errMessage = "could not get token"

	var token JWT
	var req *resty.Request

	if !NilOrEmpty(options.ClientSecret) {
		req = g.GetRequestWithBasicAuth(ctx, *options.ClientID, *options.ClientSecret)
	} else {
		req = g.GetRequest(ctx)
	}

	resp, err := req.SetFormData(options.FormData()).
		SetResult(&token).
		Post(g.getRealmURL(realm, g.Config.openIDConnect, "token"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &token, nil
}

// RevokeToken revokes the passed token. The token can either be an access or refresh token.
func (g *GoCloak) RevokeToken(ctx context.Context, realm, clientID, clientSecret, refreshToken string) error {
	const errMessage = "could not revoke token"

	resp, err := g.GetRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"client_secret": clientSecret,
			"token":         refreshToken,
		}).
		Post(g.getRealmURL(realm, g.Config.openIDConnect, "revoke"))

	return checkForError(resp, err, errMessage)
}

// Logout logs out users with refresh token
func (g *GoCloak) Logout(ctx context.Context, clientID, clientSecret, realm, refreshToken string) error {
	const errMessage = "could not logout"

	resp, err := g.GetRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"refresh_token": refreshToken,
		}).
		Post(g.getRealmURL(realm, g.Config.openIDConnect, "logout"))

	return checkForError(resp, err, errMessage)
}

// LogoutPublicClient performs a logout using a public client and the accessToken.
func (g *GoCloak) LogoutPublicClient(ctx context.Context, clientID, realm, accessToken, refreshToken string) error {
	const errMessage = "could not logout public client"

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"refresh_token": refreshToken,
		}).
		Post(g.getRealmURL(realm, g.Config.openIDConnect, "logout"))

	return checkForError(resp, err, errMessage)
}

// RefreshToken refreshes the given token.
// May return a *APIError with further details about the issue.
func (g *GoCloak) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret, realm string) (*JWT, error) {
	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("refresh_token"),
		RefreshToken: &refreshToken,
	})
}
