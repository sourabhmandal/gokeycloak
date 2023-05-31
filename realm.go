package gokeycloak

import "context"

func (g *GoKeycloak) getRealmURL(realm string, path ...string) string {
	path = append([]string{g.basePath, g.Config.authRealms, realm}, path...)
	return makeURL(path...)
}

// SetAuthRealms sets the auth realm
func SetAuthRealms(url string) func(g *GoKeycloak) {
	return func(g *GoKeycloak) {
		g.Config.authRealms = url
	}
}

// GetRealm returns top-level representation of the realm
func (g *GoKeycloak) GetRealm(ctx context.Context, token, realm string) (int, *RealmRepresentation, error) {
	const errMessage = "could not get realm"

	var result RealmRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm))

	if err = checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

// GetRealms returns top-level representation of all realms
func (g *GoKeycloak) GetRealms(ctx context.Context, token string) (int, []*RealmRepresentation, error) {
	const errMessage = "could not get realms"

	var result []*RealmRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(""))

	if err = checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), result, nil
}

// CreateRealm creates a realm
func (g *GoKeycloak) CreateRealm(ctx context.Context, token string, realm RealmRepresentation) (int, string, error) {
	const errMessage = "could not create realm"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(&realm).
		Post(g.getAdminRealmURL(""))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), "", err
	}
	return resp.StatusCode(), getID(resp), nil
}

// UpdateRealm updates a given realm
func (g *GoKeycloak) UpdateRealm(ctx context.Context, token string, realm RealmRepresentation) (int, error) {
	const errMessage = "could not update realm"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(realm).
		Put(g.getAdminRealmURL(PString(realm.Realm)))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// DeleteRealm removes a realm
func (g *GoKeycloak) DeleteRealm(ctx context.Context, token, realm string) (int, error) {
	const errMessage = "could not delete realm"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// ClearRealmCache clears realm cache
func (g *GoKeycloak) ClearRealmCache(ctx context.Context, token, realm string) (int, error) {
	const errMessage = "could not clear realm cache"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Post(g.getAdminRealmURL(realm, "clear-realm-cache"))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}
