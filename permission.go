package gokeycloak

import (
	"context"
	"net/http"

	"github.com/pkg/errors"
)

// GetPermission returns a client's permission with the given id
func (g *GoKeycloak) GetPermission(ctx context.Context, token, realm, idOfClient, permissionID string) (*PermissionRepresentation, error) {
	const errMessage = "could not get permission"

	var result PermissionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetDependentPermissions returns a client's permission with the given policy id
func (g *GoKeycloak) GetDependentPermissions(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PermissionRepresentation, error) {
	const errMessage = "could not get permission"

	var result []*PermissionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "dependentPolicies"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetPermissionResources returns a client's resource attached for the given permission id
func (g *GoKeycloak) GetPermissionResources(ctx context.Context, token, realm, idOfClient, permissionID string) ([]*PermissionResource, error) {
	const errMessage = "could not get permission resource"

	var result []*PermissionResource
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID, "resources"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetPermissionScopes returns a client's scopes configured for the given permission id
func (g *GoKeycloak) GetPermissionScopes(ctx context.Context, token, realm, idOfClient, permissionID string) ([]*PermissionScope, error) {
	const errMessage = "could not get permission scopes"

	var result []*PermissionScope
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID, "scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetPermissions returns permissions associated with the client
func (g *GoKeycloak) GetPermissions(ctx context.Context, token, realm, idOfClient string, params GetPermissionParams) ([]*PermissionRepresentation, error) {
	const errMessage = "could not get permissions"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	path := []string{"clients", idOfClient, "authz", "resource-server", "permission"}
	if !NilOrEmpty(params.Type) {
		path = append(path, *params.Type)
	}

	var result []*PermissionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, path...))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// checkPermissionTicketParams checks that mandatory fields are present
func checkPermissionTicketParams(permissions []CreatePermissionTicketParams) error {
	if len(permissions) == 0 {
		return errors.New("at least one permission ticket must be requested")
	}

	for _, pt := range permissions {

		if NilOrEmpty(pt.ResourceID) {
			return errors.New("resourceID required for permission ticket")
		}
		if NilOrEmptyArray(pt.ResourceScopes) {
			return errors.New("at least one resourceScope required for permission ticket")
		}
	}

	return nil
}

// CreatePermissionTicket creates a permission ticket, using access token from client
func (g *GoKeycloak) CreatePermissionTicket(ctx context.Context, token, realm string, permissions []CreatePermissionTicketParams) (*PermissionTicketResponseRepresentation, error) {
	const errMessage = "could not create permission ticket"

	err := checkPermissionTicketParams(permissions)
	if err != nil {
		return nil, err
	}

	var result PermissionTicketResponseRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permissions).
		Post(g.getRealmURL(realm, "authz", "protection", "permission"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// checkPermissionGrantParams checks for mandatory fields
func checkPermissionGrantParams(permission PermissionGrantParams) error {
	if NilOrEmpty(permission.RequesterID) {
		return errors.New("requesterID required to grant user permission")
	}
	if NilOrEmpty(permission.ResourceID) {
		return errors.New("resourceID required to grant user permission")
	}
	if NilOrEmpty(permission.ScopeName) {
		return errors.New("scopeName required to grant user permission")
	}

	return nil
}

// GrantUserPermission lets resource owner grant permission for specific resource ID to specific user ID
func (g *GoKeycloak) GrantUserPermission(ctx context.Context, token, realm string, permission PermissionGrantParams) (*PermissionGrantResponseRepresentation, error) {
	const errMessage = "could not grant user permission"

	err := checkPermissionGrantParams(permission)
	if err != nil {
		return nil, err
	}

	permission.Granted = BoolP(true)

	var result PermissionGrantResponseRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Post(g.getRealmURL(realm, "authz", "protection", "permission", "ticket"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// checkPermissionUpdateParams
func checkPermissionUpdateParams(permission PermissionGrantParams) error {
	err := checkPermissionGrantParams(permission)
	if err != nil {
		return err
	}

	if permission.Granted == nil {
		return errors.New("granted required to update user permission")
	}
	return nil
}

// UpdateUserPermission updates user permissions.
func (g *GoKeycloak) UpdateUserPermission(ctx context.Context, token, realm string, permission PermissionGrantParams) (*PermissionGrantResponseRepresentation, error) {
	const errMessage = "could not update user permission"

	err := checkPermissionUpdateParams(permission)
	if err != nil {
		return nil, err
	}

	var result PermissionGrantResponseRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Put(g.getRealmURL(realm, "authz", "protection", "permission", "ticket"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	if resp.StatusCode() == http.StatusNoContent { // permission updated to 'not granted' removes permission
		return nil, nil
	}

	return &result, nil
}

// GetUserPermissions gets granted permissions according query parameters
func (g *GoKeycloak) GetUserPermissions(ctx context.Context, token, realm string, params GetUserPermissionParams) ([]*PermissionGrantResponseRepresentation, error) {
	const errMessage = "could not get user permissions"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*PermissionGrantResponseRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getRealmURL(realm, "authz", "protection", "permission", "ticket"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteUserPermission revokes permissions according query parameters
func (g *GoKeycloak) DeleteUserPermission(ctx context.Context, token, realm, ticketID string) error {
	const errMessage = "could not delete user permission"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getRealmURL(realm, "authz", "protection", "permission", "ticket", ticketID))

	return checkForError(resp, err, errMessage)
}

// CreatePermission creates a permission associated with the client
func (g *GoKeycloak) CreatePermission(ctx context.Context, token, realm, idOfClient string, permission PermissionRepresentation) (*PermissionRepresentation, error) {
	const errMessage = "could not create permission"

	if NilOrEmpty(permission.Type) {
		return nil, errors.New("type of a permission required")
	}

	var result PermissionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", *(permission.Type)))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdatePermission updates a permission associated with the client
func (g *GoKeycloak) UpdatePermission(ctx context.Context, token, realm, idOfClient string, permission PermissionRepresentation) error {
	const errMessage = "could not update permission"

	if NilOrEmpty(permission.ID) {
		return errors.New("ID of a permission required")
	}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(permission).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", *permission.Type, *permission.ID))

	return checkForError(resp, err, errMessage)
}

// DeletePermission deletes a policy associated with the client
func (g *GoKeycloak) DeletePermission(ctx context.Context, token, realm, idOfClient, permissionID string) error {
	const errMessage = "could not delete permission"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID))

	return checkForError(resp, err, errMessage)
}
