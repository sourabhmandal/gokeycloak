package gokeycloak

import (
	"context"

	"github.com/pkg/errors"
)

// ------------------
// Protection API
// ------------------

// GetResource returns a client's resource with the given id, using access token from admin
func (g *GoKeycloak) GetResource(ctx context.Context, token, realm, idOfClient, resourceID string) (*ResourceRepresentation, error) {
	const errMessage = "could not get resource"

	var result ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", resourceID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResourceClient returns a client's resource with the given id, using access token from client
func (g *GoKeycloak) GetResourceClient(ctx context.Context, token, realm, resourceID string) (*ResourceRepresentation, error) {
	const errMessage = "could not get resource"

	var result ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getRealmURL(realm, "authz", "protection", "resource_set", resourceID))

	// http://${host}:${port}/auth/realms/${realm_name}/authz/protection/resource_set/{resource_id}

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResources returns resources associated with the client, using access token from admin
func (g *GoKeycloak) GetResources(ctx context.Context, token, realm, idOfClient string, params GetResourceParams) ([]*ResourceRepresentation, error) {
	const errMessage = "could not get resources"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetResourcesClient returns resources associated with the client, using access token from client
func (g *GoKeycloak) GetResourcesClient(ctx context.Context, token, realm string, params GetResourceParams) ([]*ResourceRepresentation, error) {
	const errMessage = "could not get resources"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourceRepresentation
	var resourceIDs []string
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&resourceIDs).
		SetQueryParams(queryParams).
		Get(g.getRealmURL(realm, "authz", "protection", "resource_set"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	for _, resourceID := range resourceIDs {
		resource, err := g.GetResourceClient(ctx, token, realm, resourceID)
		if err == nil {
			result = append(result, resource)
		}
	}

	return result, nil
}

// UpdateResource updates a resource associated with the client, using access token from admin
func (g *GoKeycloak) UpdateResource(ctx context.Context, token, realm, idOfClient string, resource ResourceRepresentation) error {
	const errMessage = "could not update resource"

	if NilOrEmpty(resource.ID) {
		return errors.New("ID of a resource required")
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(resource).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", *(resource.ID)))

	return checkForError(resp, err, errMessage)
}

// UpdateResourceClient updates a resource associated with the client, using access token from client
func (g *GoKeycloak) UpdateResourceClient(ctx context.Context, token, realm string, resource ResourceRepresentation) error {
	const errMessage = "could not update resource"

	if NilOrEmpty(resource.ID) {
		return errors.New("ID of a resource required")
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(resource).
		Put(g.getRealmURL(realm, "authz", "protection", "resource_set", *(resource.ID)))

	return checkForError(resp, err, errMessage)
}

// CreateResource creates a resource associated with the client, using access token from admin
func (g *GoKeycloak) CreateResource(ctx context.Context, token, realm string, idOfClient string, resource ResourceRepresentation) (*ResourceRepresentation, error) {
	const errMessage = "could not create resource"

	var result ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(resource).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// CreateResourceClient creates a resource associated with the client, using access token from client
func (g *GoKeycloak) CreateResourceClient(ctx context.Context, token, realm string, resource ResourceRepresentation) (*ResourceRepresentation, error) {
	const errMessage = "could not create resource"

	var result ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(resource).
		Post(g.getRealmURL(realm, "authz", "protection", "resource_set"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteResource deletes a resource associated with the client (using an admin token)
func (g *GoKeycloak) DeleteResource(ctx context.Context, token, realm, idOfClient, resourceID string) error {
	const errMessage = "could not delete resource"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", resourceID))

	return checkForError(resp, err, errMessage)
}

// DeleteResourceClient deletes a resource associated with the client (using a client token)
func (g *GoKeycloak) DeleteResourceClient(ctx context.Context, token, realm, resourceID string) error {
	const errMessage = "could not delete resource"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getRealmURL(realm, "authz", "protection", "resource_set", resourceID))

	return checkForError(resp, err, errMessage)
}
