package gocloak

import "context"

func (g *GoCloak) getRealmURL(realm string, path ...string) string {
	path = append([]string{g.basePath, g.Config.authRealms, realm}, path...)
	return makeURL(path...)
}

// SetAuthRealms sets the auth realm
func SetAuthRealms(url string) func(g *GoCloak) {
	return func(g *GoCloak) {
		g.Config.authRealms = url
	}
}

// GetRealm returns top-level representation of the realm
func (g *GoCloak) GetRealm(ctx context.Context, token, realm string) (*RealmRepresentation, error) {
	const errMessage = "could not get realm"

	var result RealmRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRealms returns top-level representation of all realms
func (g *GoCloak) GetRealms(ctx context.Context, token string) ([]*RealmRepresentation, error) {
	const errMessage = "could not get realms"

	var result []*RealmRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(""))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateRealm creates a realm
func (g *GoCloak) CreateRealm(ctx context.Context, token string, realm RealmRepresentation) (string, error) {
	const errMessage = "could not create realm"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(&realm).
		Post(g.getAdminRealmURL(""))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}
	return getID(resp), nil
}

// UpdateRealm updates a given realm
func (g *GoCloak) UpdateRealm(ctx context.Context, token string, realm RealmRepresentation) error {
	const errMessage = "could not update realm"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(realm).
		Put(g.getAdminRealmURL(PString(realm.Realm)))

	return checkForError(resp, err, errMessage)
}

// DeleteRealm removes a realm
func (g *GoCloak) DeleteRealm(ctx context.Context, token, realm string) error {
	const errMessage = "could not delete realm"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm))

	return checkForError(resp, err, errMessage)
}

// ClearRealmCache clears realm cache
func (g *GoCloak) ClearRealmCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear realm cache"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Post(g.getAdminRealmURL(realm, "clear-realm-cache"))

	return checkForError(resp, err, errMessage)
}
