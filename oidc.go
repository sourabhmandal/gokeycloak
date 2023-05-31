package gokeycloak

import (
	"context"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
)

// SetOpenIDConnectEndpoint sets the logout
func SetOpenIDConnectEndpoint(url string) func(g *GoKeycloak) {
	return func(g *GoKeycloak) {
		g.Config.openIDConnect = url
	}
}

// // SetRevokeEndpoint sets the revoke endpoint
// func (g *GoKeycloak) GetRevokeEndpoint() string {
// 	return g.Config.openIDConnect + "revoke"
// }

// // SetLogoutEndpoint sets the logout
// func (g *GoKeycloak) GetLogoutEndpoint() string {
// 	return g.Config.openIDConnect + "logout"
// }

//----------------------------------------------------------------------------------
//													REALM CERTIFICATES
//----------------------------------------------------------------------------------

// GetCerts fetches certificates for the given realm from the public /open-id-connect/certs endpoint
func (g *GoKeycloak) GetCerts(ctx context.Context, realm string) (int, *CertResponse, error) {
	const errMessage = "could not get certs"

	if cert, ok := g.certsCache.Load(realm); ok {
		return http.StatusBadRequest, cert.(*CertResponse), nil
	}

	g.certsLock.Lock()
	defer g.certsLock.Unlock()

	if cert, ok := g.certsCache.Load(realm); ok {
		return http.StatusBadRequest, cert.(*CertResponse), nil
	}

	statusCode, cert, err := g.getNewCerts(ctx, realm)
	if err != nil {
		return statusCode, nil, errors.Wrap(err, errMessage)
	}

	g.certsCache.Store(realm, cert)
	time.AfterFunc(g.Config.CertsInvalidateTime, func() {
		g.certsCache.Delete(realm)
	})

	return statusCode, cert, nil
}

func (g *GoKeycloak) getNewCerts(ctx context.Context, realm string) (int, *CertResponse, error) {
	const errMessage = "could not get newCerts"

	var result CertResponse
	resp, err := g.GetRequest(ctx).
		SetResult(&result).
		Get(g.getRealmURL(realm, g.Config.openIDConnect, "certs"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

//----------------------------------------------------------------------------------
//																USERINFO
//----------------------------------------------------------------------------------

// GetUserInfo calls the UserInfo endpoint
func (g *GoKeycloak) GetUserInfo(ctx context.Context, accessToken, realm string) (int, *UserInfo, error) {
	const errMessage = "could not get user info"

	var result UserInfo
	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(g.getRealmURL(realm, g.Config.openIDConnect, "userinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

// GetRawUserInfo calls the UserInfo endpoint and returns a raw json object
func (g *GoKeycloak) GetRawUserInfo(ctx context.Context, accessToken, realm string) (int, map[string]interface{}, error) {
	const errMessage = "could not get user info"

	var result map[string]interface{}
	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(g.getRealmURL(realm, g.Config.openIDConnect, "userinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), result, nil
}

//----------------------------------------------------------------------------------
//																TOKEN
//----------------------------------------------------------------------------------
// RetrospectToken calls the openid-connect introspect endpoint
func (g *GoKeycloak) IntrospectToken(ctx context.Context, accessToken, clientID, clientSecret, realm string) (int, *IntroSpectTokenResult, error) {
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
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

// URL: {{keycloak_url}}/realms/{{realm}}/protocol/openid-connect/token
// GetToken uses TokenOptions to fetch a token.
func (g *GoKeycloak) GetToken(ctx context.Context, realm string, options TokenOptions) (int, *JWT, error) {
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
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &token, nil
}

// RevokeToken revokes the passed token. The token can either be an access or refresh token.
func (g *GoKeycloak) RevokeToken(ctx context.Context, realm, clientID, clientSecret, refreshToken string) (int, error) {
	const errMessage = "could not revoke token"

	resp, err := g.GetRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"client_secret": clientSecret,
			"token":         refreshToken,
		}).
		Post(g.getRealmURL(realm, g.Config.openIDConnect, "revoke"))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// Logout logs out users with refresh token
func (g *GoKeycloak) Logout(ctx context.Context, clientID, clientSecret, realm, refreshToken string) (int, error) {
	const errMessage = "could not logout"

	resp, err := g.GetRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"refresh_token": refreshToken,
		}).
		Post(g.getRealmURL(realm, g.Config.openIDConnect, "logout"))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// LogoutPublicClient performs a logout using a public client and the accessToken.
func (g *GoKeycloak) LogoutPublicClient(ctx context.Context, clientID, realm, accessToken, refreshToken string) (int, error) {
	const errMessage = "could not logout public client"

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"refresh_token": refreshToken,
		}).
		Post(g.getRealmURL(realm, g.Config.openIDConnect, "logout"))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// RefreshToken refreshes the given token.
// May return a *APIError with further details about the issue.
func (g *GoKeycloak) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret, realm string) (int, *JWT, error) {
	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("refresh_token"),
		RefreshToken: &refreshToken,
	})
}
