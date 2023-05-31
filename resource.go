package gokeycloak

import (
	"context"
	"net/http"

	"github.com/pkg/errors"
)

// ------------------
// Protection API
// ------------------

// GetResource returns a client's resource with the given id, using access token from admin
func (g *GoKeycloak) GetResource(ctx context.Context, token, realm, idOfClient, resourceID string) (int, *ResourceRepresentation, error) {
	const errMessage = "could not get resource"

	var result ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", resourceID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

// GetResourceClient returns a client's resource with the given id, using access token from client
func (g *GoKeycloak) GetResourceClient(ctx context.Context, token, realm, resourceID string) (int, *ResourceRepresentation, error) {
	const errMessage = "could not get resource"

	var result ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getRealmURL(realm, "authz", "protection", "resource_set", resourceID))

	// http://${host}:${port}/auth/realms/${realm_name}/authz/protection/resource_set/{resource_id}

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

// GetResources returns resources associated with the client, using access token from admin
func (g *GoKeycloak) GetResources(ctx context.Context, token, realm, idOfClient string, params GetResourceParams) (int, []*ResourceRepresentation, error) {
	const errMessage = "could not get resources"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}

	var result []*ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), result, nil
}

// GetResourcesClient returns resources associated with the client, using access token from client
func (g *GoKeycloak) GetResourcesClient(ctx context.Context, token, realm string, params GetResourceParams) (int, []*ResourceRepresentation, error) {
	const errMessage = "could not get resources"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}

	var result []*ResourceRepresentation
	var resourceIDs []string
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&resourceIDs).
		SetQueryParams(queryParams).
		Get(g.getRealmURL(realm, "authz", "protection", "resource_set"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	for _, resourceID := range resourceIDs {
		_, resource, err := g.GetResourceClient(ctx, token, realm, resourceID)
		if err == nil {
			result = append(result, resource)
		}
	}

	return resp.StatusCode(), result, nil
}

// UpdateResource updates a resource associated with the client, using access token from admin
func (g *GoKeycloak) UpdateResource(ctx context.Context, token, realm, idOfClient string, resource ResourceRepresentation) (int, error) {
	const errMessage = "could not update resource"

	if NilOrEmpty(resource.ID) {
		return http.StatusBadRequest, errors.New("ID of a resource required")
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(resource).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", *(resource.ID)))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// UpdateResourceClient updates a resource associated with the client, using access token from client
func (g *GoKeycloak) UpdateResourceClient(ctx context.Context, token, realm string, resource ResourceRepresentation) (int, error) {
	const errMessage = "could not update resource"

	if NilOrEmpty(resource.ID) {
		return http.StatusBadRequest, errors.New("ID of a resource required")
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(resource).
		Put(g.getRealmURL(realm, "authz", "protection", "resource_set", *(resource.ID)))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// CreateResource creates a resource associated with the client, using access token from admin
func (g *GoKeycloak) CreateResource(ctx context.Context, token, realm string, idOfClient string, resource ResourceRepresentation) (int, *ResourceRepresentation, error) {
	const errMessage = "could not create resource"

	var result ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(resource).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

// CreateResourceClient creates a resource associated with the client, using access token from client
func (g *GoKeycloak) CreateResourceClient(ctx context.Context, token, realm string, resource ResourceRepresentation) (int, *ResourceRepresentation, error) {
	const errMessage = "could not create resource"

	var result ResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(resource).
		Post(g.getRealmURL(realm, "authz", "protection", "resource_set"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

// DeleteResource deletes a resource associated with the client (using an admin token)
func (g *GoKeycloak) DeleteResource(ctx context.Context, token, realm, idOfClient, resourceID string) (int, error) {
	const errMessage = "could not delete resource"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", resourceID))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// DeleteResourceClient deletes a resource associated with the client (using a client token)
func (g *GoKeycloak) DeleteResourceClient(ctx context.Context, token, realm, resourceID string) (int, error) {
	const errMessage = "could not delete resource"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getRealmURL(realm, "authz", "protection", "resource_set", resourceID))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}
