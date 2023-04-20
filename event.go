package gocloak

import (
	"context"

	"github.com/pkg/errors"
)

// GetEvents returns events
func (g *GoCloak) GetEvents(ctx context.Context, token string, realm string, params GetEventsParams) ([]*EventRepresentation, error) {
	const errMessage = "could not get events"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	var result []*EventRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "events"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}
