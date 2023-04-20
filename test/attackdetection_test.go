package gocloak_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/stretchr/testify/require"
)

func Test_GetUserBruteForceDetectionStatus(t *testing.T) {
	cfg := GetConfig(t)
	client := NewClientWithDebug(t)
	token := GetAdminToken(t, client)
	realm, err := client.GetRealm(
		context.Background(),
		token.AccessToken,
		cfg.GoCloak.Realm)
	require.NoError(t, err, "GetRealm failed")

	updatedRealm := realm
	updatedRealm.BruteForceProtected = gocloak.BoolP(true)
	updatedRealm.FailureFactor = gocloak.IntP(1)
	updatedRealm.MaxFailureWaitSeconds = gocloak.IntP(2)
	err = client.UpdateRealm(
		context.Background(),
		token.AccessToken,
		*updatedRealm)
	require.NoError(t, err, "UpdateRealm failed")

	tearDownUser, userID := CreateUser(t, client)
	defer tearDownUser()
	err = client.SetPassword(
		context.Background(),
		token.AccessToken,
		userID,
		*realm.ID,
		cfg.GoCloak.Password,
		false)
	require.NoError(t, err, "CreateUser failed")

	fetchedUser, err := client.GetUserByID(
		context.Background(),
		token.AccessToken,
		cfg.GoCloak.Realm,
		userID)
	require.NoError(t, err, "GetUserById failed")

	_, err = client.Login(context.Background(),
		cfg.GoCloak.ClientID,
		cfg.GoCloak.ClientSecret,
		*realm.ID,
		*fetchedUser.Username,
		"wrong password")
	require.Error(t, err, "401 Unauthorized: invalid_grant: Invalid user credentials")
	bruteForceStatus, err := client.GetUserBruteForceDetectionStatus(
		context.Background(),
		token.AccessToken,
		cfg.GoCloak.Realm,
		userID)
	require.NoError(t, err, "Getting attack log failed")
	require.Equal(t, 1, *bruteForceStatus.NumFailures, "Should return one failure")
	require.Equal(t, true, *bruteForceStatus.Disabled, "The user shouldn be locked")

	time.Sleep(2 * time.Second)
	_, err = client.Login(
		context.Background(),
		cfg.GoCloak.ClientID,
		cfg.GoCloak.ClientSecret,
		*realm.ID,
		*fetchedUser.Username,
		cfg.GoCloak.Password)
	require.NoError(t, err, "Login failed")

	bruteForceStatus, err = client.GetUserBruteForceDetectionStatus(
		context.Background(),
		token.AccessToken,
		cfg.GoCloak.Realm,
		userID)
	require.NoError(t, err, "Getting attack status failed")
	require.Equal(t, 0, *bruteForceStatus.NumFailures, "Should return zero failures")
	require.Equal(t, false, *bruteForceStatus.Disabled, "The user shouldn't be locked")

	err = client.UpdateRealm(
		context.Background(),
		token.AccessToken,
		*realm)
	require.NoError(t, err, "UpdateRealm failed")

}

func GetConfig(t testing.TB) *Config {
	configOnce.Do(func() {
		rand.Seed(time.Now().UTC().UnixNano())
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
		data, err := ioutil.ReadAll(configFile)
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
		if config.GoCloak.UserName == "" {
			config.GoCloak.UserName = "test_user"
		}
	})
	return config
}
