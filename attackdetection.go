package gokeycloak

import "context"

func (g *GoKeycloak) getAttackDetectionURL(realm string, user string, path ...string) string {
	path = append([]string{g.basePath, g.Config.authAdminRealms, realm, g.Config.attackDetection, user}, path...)
	return makeURL(path...)
}

// GetUserBruteForceDetectionStatus fetches a user status regarding brute force protection
func (g *GoKeycloak) GetUserBruteForceDetectionStatus(ctx context.Context, accessToken, realm, userID string) (*BruteForceStatus, error) {
	const errMessage = "could not brute force detection Status"
	var result BruteForceStatus

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(g.getAttackDetectionURL(realm, "users", userID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}
