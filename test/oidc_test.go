package gocloak_test

import (
	"context"
	"testing"

	"github.com/Nerzal/gocloak/v13"
	"github.com/stretchr/testify/require"
)

func Test_GetUserInfo(t *testing.T) {
	t.Parallel()
	cfg := GetConfig(t)
	client := NewClientWithDebug(t)
	SetUpTestUser(t, client)
	token := GetUserToken(t, client)
	userInfo, err := client.GetUserInfo(
		context.Background(),
		token.AccessToken,
		cfg.GoCloak.Realm,
	)
	require.NoError(t, err, "Failed to fetch userinfo")
	t.Log(userInfo)
	FailRequest(client, nil, 1, 0)
	_, err = client.GetUserInfo(
		context.Background(),
		token.AccessToken,
		cfg.GoCloak.Realm)
	require.Error(t, err, "")
}

func Test_GetRawUserInfo(t *testing.T) {
	t.Parallel()
	cfg := GetConfig(t)
	client := NewClientWithDebug(t)
	SetUpTestUser(t, client)
	token := GetUserToken(t, client)
	userInfo, err := client.GetUserInfo(
		context.Background(),
		token.AccessToken,
		cfg.GoCloak.Realm,
	)
	require.NoError(t, err, "Failed to fetch userinfo")
	t.Log(userInfo)
	require.NotEmpty(t, userInfo)
}

func Test_GetToken(t *testing.T) {
	t.Parallel()
	cfg := GetConfig(t)
	client := NewClientWithDebug(t)
	SetUpTestUser(t, client)
	newToken, err := client.GetToken(
		context.Background(),
		cfg.GoCloak.Realm,
		gocloak.TokenOptions{
			ClientID:      &cfg.GoCloak.ClientID,
			ClientSecret:  &cfg.GoCloak.ClientSecret,
			Username:      &cfg.GoCloak.UserName,
			Password:      &cfg.GoCloak.Password,
			GrantType:     gocloak.StringP("password"),
			ResponseTypes: &[]string{"token", "id_token"},
			Scopes:        &[]string{"openid", "offline_access"},
		},
	)
	require.NoError(t, err, "Login failed")
	t.Logf("New token: %+v", *newToken)
	require.Equal(t, newToken.RefreshExpiresIn, 0, "Got a refresh token instead of offline")
	require.NotEmpty(t, newToken.IDToken, "Got an empty if token")
}

func GetClientToken(t *testing.T, client *gocloak.GoCloak) *gocloak.JWT {
	cfg := GetConfig(t)
	token, err := client.LoginClient(
		context.Background(),
		cfg.GoCloak.ClientID,
		cfg.GoCloak.ClientSecret,
		cfg.GoCloak.Realm)
	require.NoError(t, err, "Login failed")
	return token
}

func GetUserToken(t *testing.T, client *gocloak.GoCloak) *gocloak.JWT {
	SetUpTestUser(t, client)
	cfg := GetConfig(t)
	token, err := client.Login(
		context.Background(),
		cfg.GoCloak.ClientID,
		cfg.GoCloak.ClientSecret,
		cfg.GoCloak.Realm,
		cfg.GoCloak.UserName,
		cfg.GoCloak.Password)
	require.NoError(t, err, "Login failed")
	return token
}

func GetAdminToken(t testing.TB, client *gocloak.GoCloak) *gocloak.JWT {
	cfg := GetConfig(t)
	token, err := client.LoginAdmin(
		context.Background(),
		cfg.Admin.UserName,
		cfg.Admin.Password,
		cfg.Admin.Realm)
	require.NoError(t, err, "Login Admin failed")
	return token
}

func Test_RevokeToken(t *testing.T) {
	t.Parallel()
	cfg := GetConfig(t)
	client := NewClientWithDebug(t)
	SetUpTestUser(t, client)
	token := GetUserToken(t, client)
	err := client.RevokeToken(
		context.Background(),
		cfg.GoCloak.Realm,
		cfg.GoCloak.ClientID,
		cfg.GoCloak.ClientSecret,
		token.RefreshToken,
	)
	require.NoError(t, err, "Revoke failed")
}

func Test_RetrospectRequestingPartyToken(t *testing.T) {
	t.Parallel()
	cfg := GetConfig(t)
	client := NewClientWithDebug(t)
	SetUpTestUser(t, client)
	token, err := client.Login(
		context.Background(),
		cfg.GoCloak.ClientID,
		cfg.GoCloak.ClientSecret,
		cfg.GoCloak.Realm,
		cfg.GoCloak.UserName,
		cfg.GoCloak.Password)
	require.NoError(t, err, "login failed")

	rpt, err := client.GetRequestingPartyToken(
		context.Background(),
		token.AccessToken,
		cfg.GoCloak.Realm,
		gocloak.RequestingPartyTokenOptions{
			Audience: gocloak.StringP(cfg.GoCloak.ClientID),
			Permissions: &[]string{
				"Fake Resource",
			},
		})
	require.Error(t, err, "GetRequestingPartyToken must fail with Fake resource")
	require.Nil(t, rpt)

	rpt, err = client.GetRequestingPartyToken(
		context.Background(),
		token.AccessToken,
		cfg.GoCloak.Realm,
		gocloak.RequestingPartyTokenOptions{
			Audience: gocloak.StringP(cfg.GoCloak.ClientID),
			Permissions: &[]string{
				"Default Resource",
			},
		})
	require.NoError(t, err, "GetRequestingPartyToken failed")
	require.NotNil(t, rpt)

	rptResult, err := client.IntrospectToken(
		context.Background(),
		rpt.AccessToken,
		cfg.GoCloak.ClientID,
		cfg.GoCloak.ClientSecret,
		cfg.GoCloak.Realm,
	)
	t.Log(rptResult)
	require.NoError(t, err, "inspection failed")
	require.True(t, gocloak.PBool(rptResult.Active), "Inactive Token oO")
	require.NotNil(t, *rptResult.Permissions)
	permissions := *rptResult.Permissions
	require.Len(t, permissions, 1, "GetRequestingPartyToken failed")
	require.Equal(t, "Default Resource", *permissions[0].RSName, "GetRequestingPartyToken failed")
}

func Test_GetServerInfo(t *testing.T) {
	t.Parallel()
	client := NewClientWithDebug(t)
	// client.RestyClient().SetDebug(true)
	token := GetAdminToken(t, client)
	serverInfo, err := client.GetAllRealmsInfo(
		context.Background(),
		token.AccessToken,
	)
	require.NoError(t, err, "Failed to fetch server info")
	t.Logf("Server Info: %+v", serverInfo)

	FailRequest(client, nil, 1, 0)
	_, err = client.GetAllRealmsInfo(
		context.Background(),
		token.AccessToken,
	)
	require.Error(t, err)
}

func Test_Logout(t *testing.T) {
	t.Parallel()
	cfg := GetConfig(t)
	client := NewClientWithDebug(t)
	token := GetUserToken(t, client)

	err := client.Logout(
		context.Background(),
		cfg.GoCloak.ClientID,
		cfg.GoCloak.ClientSecret,
		cfg.GoCloak.Realm,
		token.RefreshToken)
	require.NoError(t, err, "Logout failed")
}
