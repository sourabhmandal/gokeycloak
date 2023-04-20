package gokeycloak

import (
	"context"
)

func (g *GoKeycloak) getAdminRealmURL(realm string, path ...string) string {
	path = append([]string{g.basePath, g.Config.authAdminRealms, realm}, path...)
	return makeURL(path...)
}

// SetLegacyWildFlySupport maintain legacy WildFly support.
func SetLegacyWildFlySupport() func(g *GoKeycloak) {
	return func(g *GoKeycloak) {
		g.Config.authAdminRealms = makeURL("auth", "admin", "realms")
		g.Config.authRealms = makeURL("auth", "realms")
	}
}

// SetAuthAdminRealms sets the auth admin realm
func SetAuthAdminRealms(url string) func(g *GoKeycloak) {
	return func(g *GoKeycloak) {
		g.Config.authAdminRealms = url
	}
}

// URL: {{keycloak_url}}/admin/realms
// GetServerInfo fetches the server info.
func (g *GoKeycloak) GetAllRealmsInfo(ctx context.Context, adminAccessToken string) ([]*ServerInfoRepresentation, error) {
	errMessage := "could not get server info"
	var result []*ServerInfoRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, adminAccessToken).
		SetResult(&result).
		Get(makeURL(g.basePath, "admin", "realms"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// LogoutAllSessions logs out all sessions of a user given an id.
func (g *GoKeycloak) LogoutAllSessions(ctx context.Context, adminAccessToken, realm, userID string) error {
	const errMessage = "could not logout"

	resp, err := g.GetRequestWithBearerAuth(ctx, adminAccessToken).
		Post(g.getAdminRealmURL(realm, "users", userID, "logout"))

	return checkForError(resp, err, errMessage)
}

// SendVerifyEmail sends a verification e-mail to a user.
func (g *GoKeycloak) SendVerifyEmail(ctx context.Context, token, userID, realm string, params ...SendVerificationMailParams) error {
	const errMessage = "could not execute actions email"

	queryParams := map[string]string{}
	if params != nil {
		if params[0].ClientID != nil {
			queryParams["client_id"] = *params[0].ClientID
		}

		if params[0].RedirectURI != nil {
			queryParams["redirect_uri"] = *params[0].RedirectURI
		}
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetQueryParams(queryParams).
		Put(g.getAdminRealmURL(realm, "users", userID, "send-verify-email"))

	return checkForError(resp, err, errMessage)
}
