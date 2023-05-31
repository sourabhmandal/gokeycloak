package gokeycloak

import (
	"context"
	"net/http"

	"github.com/pkg/errors"
)

// GetScope returns a client's scope with the given id
func (g *GoKeycloak) GetScope(ctx context.Context, token, realm, idOfClient, scopeID string) (int, *ScopeRepresentation, error) {
	const errMessage = "could not get scope"

	var result ScopeRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", scopeID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

// GetScopes returns scopes associated with the client
func (g *GoKeycloak) GetScopes(ctx context.Context, token, realm, idOfClient string, params GetScopeParams) (int, []*ScopeRepresentation, error) {
	const errMessage = "could not get scopes"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	var result []*ScopeRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), result, nil
}

// CreateScope creates a scope associated with the client
func (g *GoKeycloak) CreateScope(ctx context.Context, token, realm, idOfClient string, scope ScopeRepresentation) (int, *ScopeRepresentation, error) {
	const errMessage = "could not create scope"

	var result ScopeRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(scope).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

// UpdateScope updates a scope associated with the client
func (g *GoKeycloak) UpdateScope(ctx context.Context, token, realm, idOfClient string, scope ScopeRepresentation) (int, error) {
	const errMessage = "could not update scope"

	if NilOrEmpty(scope.ID) {
		return http.StatusBadRequest, errors.New("ID of a scope required")
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", *(scope.ID)))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// DeleteScope deletes a scope associated with the client
func (g *GoKeycloak) DeleteScope(ctx context.Context, token, realm, idOfClient, scopeID string) (int, error) {
	const errMessage = "could not delete scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", scopeID))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}
