package gokeycloak

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
)

// GetComponents get all components in realm
func (g *GoKeycloak) GetComponents(ctx context.Context, token, realm string) ([]*Component, error) {
	const errMessage = "could not get components"

	var result []*Component
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "components"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetComponentsWithParams get all components in realm with query params
func (g *GoKeycloak) GetComponentsWithParams(ctx context.Context, token, realm string, params GetComponentsParams) ([]*Component, error) {
	const errMessage = "could not get components"
	var result []*Component

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "components"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetComponent get exactly one component by ID
func (g *GoKeycloak) GetComponent(ctx context.Context, token, realm string, componentID string) (*Component, error) {
	const errMessage = "could not get components"
	var result *Component

	componentURL := fmt.Sprintf("components/%s", componentID)

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, componentURL))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateComponent updates the given component
func (g *GoKeycloak) UpdateComponent(ctx context.Context, token, realm string, component Component) error {
	const errMessage = "could not update component"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(component).
		Put(g.getAdminRealmURL(realm, "components", PString(component.ID)))

	return checkForError(resp, err, errMessage)
}

// GetDefaultGroups returns a list of default groups
func (g *GoKeycloak) GetDefaultGroups(ctx context.Context, token, realm string) ([]*Group, error) {
	const errMessage = "could not get default groups"

	var result []*Group

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "default-groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddDefaultGroup adds group to the list of default groups
func (g *GoKeycloak) AddDefaultGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not add default group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Put(g.getAdminRealmURL(realm, "default-groups", groupID))

	return checkForError(resp, err, errMessage)
}

// RemoveDefaultGroup removes group from the list of default groups
func (g *GoKeycloak) RemoveDefaultGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not remove default group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "default-groups", groupID))

	return checkForError(resp, err, errMessage)
}
