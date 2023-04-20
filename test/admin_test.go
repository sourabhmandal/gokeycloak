package gocloak_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_LogoutAllSessions(t *testing.T) {
	t.Parallel()
	cfg := GetConfig(t)
	client := NewClientWithDebug(t)
	token := GetAdminToken(t, client)

	tearDown, userID := CreateUser(t, client)
	defer tearDown()

	err := client.LogoutAllSessions(
		context.Background(),
		token.AccessToken,
		cfg.GoCloak.Realm,
		userID,
	)
	require.NoError(t, err, "Logout failed")
}
