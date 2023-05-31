package gokeycloak_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sourabhmandal/gokeycloak"
	"github.com/stretchr/testify/require"
)

func Test_GetUserBruteForceDetectionStatus(t *testing.T) {
	cfg := GetConfig(t)
	client := NewClientWithDebug(t)
	token := GetAdminToken(t, client)
	_, realm, err := client.GetRealm(
		context.Background(),
		token.AccessToken,
		cfg.GoKeycloak.Realm)
	require.NoError(t, err, "GetRealm failed")

	updatedRealm := realm
	updatedRealm.BruteForceProtected = gokeycloak.BoolP(true)
	updatedRealm.FailureFactor = gokeycloak.IntP(1)
	updatedRealm.MaxFailureWaitSeconds = gokeycloak.IntP(2)
	_, err = client.UpdateRealm(
		context.Background(),
		token.AccessToken,
		*updatedRealm)
	require.NoError(t, err, "UpdateRealm failed")

	tearDownUser, userID := CreateUser(t, client)
	defer tearDownUser()
	_, err = client.SetPassword(
		context.Background(),
		token.AccessToken,
		userID,
		*realm.ID,
		cfg.GoKeycloak.Password,
		false)
	require.NoError(t, err, "CreateUser failed")

	_, fetchedUser, err := client.GetUserByID(
		context.Background(),
		token.AccessToken,
		cfg.GoKeycloak.Realm,
		userID)
	require.NoError(t, err, "GetUserById failed")

	_, _, err = client.Login(context.Background(),
		cfg.GoKeycloak.ClientID,
		cfg.GoKeycloak.ClientSecret,
		*realm.ID,
		*fetchedUser.Username,
		"wrong password")
	require.Error(t, err, "401 Unauthorized: invalid_grant: Invalid user credentials")
	bruteForceStatus, err := client.GetUserBruteForceDetectionStatus(
		context.Background(),
		token.AccessToken,
		cfg.GoKeycloak.Realm,
		userID)
	require.NoError(t, err, "Getting attack log failed")
	require.Equal(t, 1, *bruteForceStatus.NumFailures, "Should return one failure")
	require.Equal(t, true, *bruteForceStatus.Disabled, "The user shouldn be locked")

	time.Sleep(2 * time.Second)
	_, _, err = client.Login(
		context.Background(),
		cfg.GoKeycloak.ClientID,
		cfg.GoKeycloak.ClientSecret,
		*realm.ID,
		*fetchedUser.Username,
		cfg.GoKeycloak.Password)
	require.NoError(t, err, "Login failed")

	bruteForceStatus, err = client.GetUserBruteForceDetectionStatus(
		context.Background(),
		token.AccessToken,
		cfg.GoKeycloak.Realm,
		userID)
	require.NoError(t, err, "Getting attack status failed")
	require.Equal(t, 0, *bruteForceStatus.NumFailures, "Should return zero failures")
	require.Equal(t, false, *bruteForceStatus.Disabled, "The user shouldn't be locked")

	_, err = client.UpdateRealm(
		context.Background(),
		token.AccessToken,
		*realm)
	require.NoError(t, err, "UpdateRealm failed")

}

func GetConfig(t testing.TB) *Config {
	configOnce.Do(func() {
		rand.NewSource(time.Now().UTC().UnixNano())
		configFileName, ok := os.LookupEnv("GOCLOAK_TEST_CONFIG")
		if !ok {
			configFileName = filepath.Join("testdata", "config.json")
		}
		configFile, err := os.Open(configFileName)
		require.NoError(t, err, "cannot open config.json")
		defer func() {
			err := configFile.Close()
			require.NoError(t, err, "cannot close config file")
		}()
		data, err := io.ReadAll(configFile)
		require.NoError(t, err, "cannot read config.json")
		config = &Config{}
		err = json.Unmarshal(data, config)
		require.NoError(t, err, "cannot parse config.json")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		if len(config.Proxy) != 0 {
			proxy, err := url.Parse(config.Proxy)
			require.NoError(t, err, "incorrect proxy url: "+config.Proxy)
			http.DefaultTransport.(*http.Transport).Proxy = http.ProxyURL(proxy)
		}
		if config.GoKeycloak.UserName == "" {
			config.GoKeycloak.UserName = "test_user"
		}
	})
	return config
}
