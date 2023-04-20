package gocloak

import "context"

// ---------------
// Credentials API
// ---------------

// GetCredentialRegistrators returns credentials registrators
func (g *GoCloak) GetCredentialRegistrators(ctx context.Context, token, realm string) ([]string, error) {
	const errMessage = "could not get user credential registrators"

	var result []string
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "credential-registrators"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetConfiguredUserStorageCredentialTypes returns credential types, which are provided by the user storage where user is stored
func (g *GoCloak) GetConfiguredUserStorageCredentialTypes(ctx context.Context, token, realm, userID string) ([]string, error) {
	const errMessage = "could not get user credential registrators"

	var result []string
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "users", userID, "configured-user-storage-credential-types"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCredentials returns credentials available for a given user
func (g *GoCloak) GetCredentials(ctx context.Context, token, realm, userID string) ([]*CredentialRepresentation, error) {
	const errMessage = "could not get user credentials"

	var result []*CredentialRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "users", userID, "credentials"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteCredentials deletes the given credential for a given user
func (g *GoCloak) DeleteCredentials(ctx context.Context, token, realm, userID, credentialID string) error {
	const errMessage = "could not delete user credentials"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "users", userID, "credentials", credentialID))

	return checkForError(resp, err, errMessage)
}

// UpdateCredentialUserLabel updates label for the given credential for the given user
func (g *GoCloak) UpdateCredentialUserLabel(ctx context.Context, token, realm, userID, credentialID, userLabel string) error {
	const errMessage = "could not update credential label for a user"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetHeader("Content-Type", "text/plain").
		SetBody(userLabel).
		Put(g.getAdminRealmURL(realm, "users", userID, "credentials", credentialID, "userLabel"))

	return checkForError(resp, err, errMessage)
}

// DisableAllCredentialsByType disables all credentials for a user of a specific type
func (g *GoCloak) DisableAllCredentialsByType(ctx context.Context, token, realm, userID string, types []string) error {
	const errMessage = "could not update disable credentials"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(types).
		Put(g.getAdminRealmURL(realm, "users", userID, "disable-credential-types"))

	return checkForError(resp, err, errMessage)
}

// MoveCredentialBehind move a credential to a position behind another credential
func (g *GoCloak) MoveCredentialBehind(ctx context.Context, token, realm, userID, credentialID, newPreviousCredentialID string) error {
	const errMessage = "could not move credential"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Post(g.getAdminRealmURL(realm, "users", userID, "credentials", credentialID, "moveAfter", newPreviousCredentialID))

	return checkForError(resp, err, errMessage)
}

// MoveCredentialToFirst move a credential to a first position in the credentials list of the user
func (g *GoCloak) MoveCredentialToFirst(ctx context.Context, token, realm, userID, credentialID string) error {
	const errMessage = "could not move credential"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Post(g.getAdminRealmURL(realm, "users", userID, "credentials", credentialID, "moveToFirst"))

	return checkForError(resp, err, errMessage)
}
