package gocloak

import (
	"context"

	"github.com/pkg/errors"
)

// GetPolicy returns a client's policy with the given id
func (g *GoCloak) GetPolicy(ctx context.Context, token, realm, idOfClient, policyID string) (*PolicyRepresentation, error) {
	const errMessage = "could not get policy"

	var result PolicyRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetPolicies returns policies associated with the client
func (g *GoCloak) GetPolicies(ctx context.Context, token, realm, idOfClient string, params GetPolicyParams) ([]*PolicyRepresentation, error) {
	const errMessage = "could not get policies"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	path := []string{"clients", idOfClient, "authz", "resource-server", "policy"}
	if !NilOrEmpty(params.Type) {
		path = append(path, *params.Type)
	}

	var result []*PolicyRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, path...))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreatePolicy creates a policy associated with the client
func (g *GoCloak) CreatePolicy(ctx context.Context, token, realm, idOfClient string, policy PolicyRepresentation) (*PolicyRepresentation, error) {
	const errMessage = "could not create policy"

	if NilOrEmpty(policy.Type) {
		return nil, errors.New("type of a policy required")
	}

	var result PolicyRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(policy).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", *(policy.Type)))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdatePolicy updates a policy associated with the client
func (g *GoCloak) UpdatePolicy(ctx context.Context, token, realm, idOfClient string, policy PolicyRepresentation) error {
	const errMessage = "could not update policy"

	if NilOrEmpty(policy.ID) {
		return errors.New("ID of a policy required")
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(policy).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", *(policy.Type), *(policy.ID)))

	return checkForError(resp, err, errMessage)
}

// DeletePolicy deletes a policy associated with the client
func (g *GoCloak) DeletePolicy(ctx context.Context, token, realm, idOfClient, policyID string) error {
	const errMessage = "could not delete policy"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID))

	return checkForError(resp, err, errMessage)
}

// GetAuthorizationPolicyAssociatedPolicies returns a client's associated policies of specific policy with the given policy id, using access token from admin
func (g *GoCloak) GetAuthorizationPolicyAssociatedPolicies(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PolicyRepresentation, error) {
	const errMessage = "could not get policy associated policies"

	var result []*PolicyRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "associatedPolicies"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAuthorizationPolicyResources returns a client's resources of specific policy with the given policy id, using access token from admin
func (g *GoCloak) GetAuthorizationPolicyResources(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PolicyResourceRepresentation, error) {
	const errMessage = "could not get policy resources"

	var result []*PolicyResourceRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "resources"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAuthorizationPolicyScopes returns a client's scopes of specific policy with the given policy id, using access token from admin
func (g *GoCloak) GetAuthorizationPolicyScopes(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PolicyScopeRepresentation, error) {
	const errMessage = "could not get policy scopes"

	var result []*PolicyScopeRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetResourcePolicy updates a permission for a specific resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (g *GoCloak) GetResourcePolicy(ctx context.Context, token, realm, permissionID string) (*ResourcePolicyRepresentation, error) {
	const errMessage = "could not get resource policy"

	var result ResourcePolicyRepresentation
	resp, err := g.GetRequestWithBearerAuthNoCache(ctx, token).
		SetResult(&result).
		Get(g.getRealmURL(realm, "authz", "protection", "uma-policy", permissionID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResourcePolicies returns resources associated with the client, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (g *GoCloak) GetResourcePolicies(ctx context.Context, token, realm string, params GetResourcePoliciesParams) ([]*ResourcePolicyRepresentation, error) {
	const errMessage = "could not get resource policies"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourcePolicyRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getRealmURL(realm, "authz", "protection", "uma-policy"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateResourcePolicy associates a permission with a specific resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (g *GoCloak) CreateResourcePolicy(ctx context.Context, token, realm, resourceID string, policy ResourcePolicyRepresentation) (*ResourcePolicyRepresentation, error) {
	const errMessage = "could not create resource policy"

	var result ResourcePolicyRepresentation
	resp, err := g.GetRequestWithBearerAuthNoCache(ctx, token).
		SetResult(&result).
		SetBody(policy).
		Post(g.getRealmURL(realm, "authz", "protection", "uma-policy", resourceID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateResourcePolicy updates a permission for a specific resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (g *GoCloak) UpdateResourcePolicy(ctx context.Context, token, realm, permissionID string, policy ResourcePolicyRepresentation) error {
	const errMessage = "could not update resource policy"

	resp, err := g.GetRequestWithBearerAuthNoCache(ctx, token).
		SetBody(policy).
		Put(g.getRealmURL(realm, "authz", "protection", "uma-policy", permissionID))

	return checkForError(resp, err, errMessage)
}

// DeleteResourcePolicy deletes a permission for a specific resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (g *GoCloak) DeleteResourcePolicy(ctx context.Context, token, realm, permissionID string) error {
	const errMessage = "could not  delete resource policy"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getRealmURL(realm, "authz", "protection", "uma-policy", permissionID))

	return checkForError(resp, err, errMessage)
}
