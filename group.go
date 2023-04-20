package gokeycloak

import (
	"context"

	"github.com/pkg/errors"
)

// CreateGroup creates a new group.
func (g *GoKeycloak) CreateGroup(ctx context.Context, token, realm string, group Group) (string, error) {
	const errMessage = "could not create group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(group).
		Post(g.getAdminRealmURL(realm, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}
	return getID(resp), nil
}

// CreateChildGroup creates a new child group
func (g *GoKeycloak) CreateChildGroup(ctx context.Context, token, realm, groupID string, group Group) (string, error) {
	const errMessage = "could not create child group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(group).
		Post(g.getAdminRealmURL(realm, "groups", groupID, "children"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// UpdateGroup updates the given group.
func (g *GoKeycloak) UpdateGroup(ctx context.Context, token, realm string, updatedGroup Group) error {
	const errMessage = "could not update group"

	if NilOrEmpty(updatedGroup.ID) {
		return errors.Wrap(errors.New("ID of a group required"), errMessage)
	}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(updatedGroup).
		Put(g.getAdminRealmURL(realm, "groups", PString(updatedGroup.ID)))

	return checkForError(resp, err, errMessage)
}

// DeleteGroup deletes the group with the given groupID.
func (g *GoKeycloak) DeleteGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not delete group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// GetGroup get group with id in realm
func (g *GoKeycloak) GetGroup(ctx context.Context, token, realm, groupID string) (*Group, error) {
	const errMessage = "could not get group"

	var result Group

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "groups", groupID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetGroupByPath get group with path in realm
func (g *GoKeycloak) GetGroupByPath(ctx context.Context, token, realm, groupPath string) (*Group, error) {
	const errMessage = "could not get group"

	var result Group

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "group-by-path", groupPath))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetGroups get all groups in realm
func (g *GoKeycloak) GetGroups(ctx context.Context, token, realm string, params GetGroupsParams) ([]*Group, error) {
	const errMessage = "could not get groups"

	var result []*Group
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetGroupsByRole gets groups assigned with a specific role of a realm
func (g *GoKeycloak) GetGroupsByRole(ctx context.Context, token, realm string, roleName string) ([]*Group, error) {
	const errMessage = "could not get groups"

	var result []*Group
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "roles", roleName, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetGroupsByClientRole gets groups with specified roles assigned of given client within a realm
func (g *GoKeycloak) GetGroupsByClientRole(ctx context.Context, token, realm string, roleName string, clientID string) ([]*Group, error) {
	const errMessage = "could not get groups"

	var result []*Group
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", clientID, "roles", roleName, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetGroupsCount gets the groups count in the realm
func (g *GoKeycloak) GetGroupsCount(ctx context.Context, token, realm string, params GetGroupsParams) (int, error) {
	const errMessage = "could not get groups count"

	var result GroupsCount
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return 0, errors.Wrap(err, errMessage)
	}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "groups", "count"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return -1, errors.Wrap(err, errMessage)
	}

	return result.Count, nil
}

// GetGroupMembers get a list of users of group with id in realm
func (g *GoKeycloak) GetGroupMembers(ctx context.Context, token, realm, groupID string, params GetGroupsParams) ([]*User, error) {
	const errMessage = "could not get group members"

	var result []*User
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "groups", groupID, "members"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddClientRolesToGroup adds a client role to the group
func (g *GoKeycloak) AddClientRolesToGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error {
	const errMessage = "could not add client role to group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(g.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// AddClientRoleToGroup adds a client role to the group
//
// Deprecated: replaced by AddClientRolesToGroup
func (g *GoKeycloak) AddClientRoleToGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error {
	return g.AddClientRolesToGroup(ctx, token, realm, idOfClient, groupID, roles)
}

// DeleteClientRoleFromGroup removes a client role from from the group
func (g *GoKeycloak) DeleteClientRoleFromGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error {
	const errMessage = "could not client role from group"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(g.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}
