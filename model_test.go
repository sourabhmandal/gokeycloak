package gokeycloak_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/zblocks/gokeycloak"

	"github.com/stretchr/testify/assert"
)

func TestStringOrArray_Unmarshal(t *testing.T) {
	t.Parallel()
	jsonString := []byte("\"123\"")
	var dataString gokeycloak.StringOrArray
	err := json.Unmarshal(jsonString, &dataString)
	assert.NoErrorf(t, err, "Unmarshalling failed for json string: %s", jsonString)
	assert.Len(t, dataString, 1)
	assert.Equal(t, "123", dataString[0])

	jsonArray := []byte("[\"1\",\"2\",\"3\"]")
	var dataArray gokeycloak.StringOrArray
	err = json.Unmarshal(jsonArray, &dataArray)
	assert.NoError(t, err, "Unmarshalling failed for json array of strings: %s", jsonArray)
	assert.Len(t, dataArray, 3)
	assert.EqualValues(t, []string{"1", "2", "3"}, dataArray)
}

func TestStringOrArray_Marshal(t *testing.T) {
	t.Parallel()
	dataString := gokeycloak.StringOrArray{"123"}
	jsonString, err := json.Marshal(&dataString)
	assert.NoErrorf(t, err, "Marshaling failed for one string: %s", dataString)
	assert.Equal(t, "\"123\"", string(jsonString))

	dataArray := gokeycloak.StringOrArray{"1", "2", "3"}
	jsonArray, err := json.Marshal(&dataArray)
	assert.NoError(t, err, "Marshaling failed for array of strings: %s", dataArray)
	assert.Equal(t, "[\"1\",\"2\",\"3\"]", string(jsonArray))
}

func TestEnforcedString_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	type testData struct {
		In  []byte
		Out gokeycloak.EnforcedString
	}

	data := []testData{{
		In:  []byte(`"string value"`),
		Out: "string value",
	}, {
		In:  []byte(`"\"quoted string value\""`),
		Out: `"quoted string value"`,
	}, {
		In:  []byte(`true`),
		Out: "true",
	}, {
		In:  []byte(`42`),
		Out: "42",
	}, {
		In:  []byte(`{"foo": "bar"}`),
		Out: `{"foo": "bar"}`,
	}, {
		In:  []byte(`["foo"]`),
		Out: `["foo"]`,
	}}

	for _, d := range data {
		var val gokeycloak.EnforcedString
		err := json.Unmarshal(d.In, &val)
		assert.NoErrorf(t, err, "Unmarshalling failed with data: %v", d.In)
		assert.Equal(t, d.Out, val)
	}
}

func TestEnforcedString_MarshalJSON(t *testing.T) {
	t.Parallel()

	data := gokeycloak.EnforcedString("foo")
	jsonString, err := json.Marshal(&data)
	assert.NoErrorf(t, err, "Unmarshalling failed with data: %v", data)
	assert.Equal(t, `"foo"`, string(jsonString))
}

func TestGetQueryParams(t *testing.T) {
	t.Parallel()

	type TestParams struct {
		IntField    *int    `json:"int_field,string,omitempty"`
		StringField *string `json:"string_field,omitempty"`
		BoolField   *bool   `json:"bool_field,string,omitempty"`
	}

	params, err := gokeycloak.GetQueryParams(TestParams{})
	assert.NoError(t, err)
	assert.True(
		t,
		len(params) == 0,
		"Params must be empty, but got: %+v",
		params,
	)

	params, err = gokeycloak.GetQueryParams(TestParams{
		IntField:    gokeycloak.IntP(1),
		StringField: gokeycloak.StringP("fake"),
		BoolField:   gokeycloak.BoolP(true),
	})
	assert.NoError(t, err)
	assert.Equal(
		t,
		map[string]string{
			"int_field":    "1",
			"string_field": "fake",
			"bool_field":   "true",
		},
		params,
	)

	params, err = gokeycloak.GetQueryParams(TestParams{
		StringField: gokeycloak.StringP("fake"),
		BoolField:   gokeycloak.BoolP(false),
	})
	assert.NoError(t, err)
	assert.Equal(
		t,
		map[string]string{
			"string_field": "fake",
			"bool_field":   "false",
		},
		params,
	)
}

func TestParseAPIErrType(t *testing.T) {
	testCases := []struct {
		Name     string
		Error    error
		Expected gokeycloak.APIErrType
	}{
		{
			Name:     "nil error",
			Error:    nil,
			Expected: gokeycloak.APIErrTypeUnknown,
		},
		{
			Name:     "invalid grant",
			Error:    errors.New("something something invalid_grant something"),
			Expected: gokeycloak.APIErrTypeInvalidGrant,
		},
		{
			Name:     "other error",
			Error:    errors.New("something something unsupported_grant_type something"),
			Expected: gokeycloak.APIErrTypeUnknown,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			result := gokeycloak.ParseAPIErrType(testCase.Error)
			if result != testCase.Expected {
				t.Fatalf("expected %s but received %s", testCase.Expected, result)
			}
		})
	}
}

func TestStringer(t *testing.T) {
	// nested structs
	actions := []string{"someAction", "anotherAction"}
	access := gokeycloak.AccessRepresentation{
		Manage:      gokeycloak.BoolP(true),
		Impersonate: gokeycloak.BoolP(false),
	}
	v := gokeycloak.PermissionTicketDescriptionRepresentation{
		ID:               gokeycloak.StringP("someID"),
		CreatedTimeStamp: gokeycloak.Int64P(1607702613),
		Enabled:          gokeycloak.BoolP(true),
		RequiredActions:  &actions,
		Access:           &access,
	}

	str := v.String()

	expectedStr := `{
	"id": "someID",
	"createdTimestamp": 1607702613,
	"enabled": true,
	"requiredActions": [
		"someAction",
		"anotherAction"
	],
	"access": {
		"impersonate": false,
		"manage": true
	}
}`

	assert.Equal(t, expectedStr, str)

	// nested arrays
	config := make(map[string]string)
	config["bar"] = "foo"
	config["ping"] = "pong"

	pmappers := []gokeycloak.ProtocolMapperRepresentation{
		{
			Name:   gokeycloak.StringP("someMapper"),
			Config: &config,
		},
	}
	clients := []gokeycloak.Client{
		{
			Name:            gokeycloak.StringP("someClient"),
			ProtocolMappers: &pmappers,
		},
		{
			Name: gokeycloak.StringP("AnotherClient"),
		},
	}

	realmRep := gokeycloak.RealmRepresentation{
		DisplayName: gokeycloak.StringP("someRealm"),
		Clients:     &clients,
	}

	str = realmRep.String()
	expectedStr = `{
	"clients": [
		{
			"name": "someClient",
			"protocolMappers": [
				{
					"config": {
						"bar": "foo",
						"ping": "pong"
					},
					"name": "someMapper"
				}
			]
		},
		{
			"name": "AnotherClient"
		}
	],
	"displayName": "someRealm"
}`
	assert.Equal(t, expectedStr, str)
}

type Stringable interface {
	String() string
}

func TestStringerOmitEmpty(t *testing.T) {
	customs := []Stringable{
		&gokeycloak.CertResponseKey{},
		&gokeycloak.CertResponse{},
		&gokeycloak.IssuerResponse{},
		&gokeycloak.ResourcePermission{},
		&gokeycloak.PermissionResource{},
		&gokeycloak.PermissionScope{},
		&gokeycloak.IntroSpectTokenResult{},
		&gokeycloak.User{},
		&gokeycloak.SetPasswordRequest{},
		&gokeycloak.Component{},
		&gokeycloak.KeyStoreConfig{},
		&gokeycloak.ActiveKeys{},
		&gokeycloak.Key{},
		&gokeycloak.Attributes{},
		&gokeycloak.Access{},
		&gokeycloak.UserGroup{},
		&gokeycloak.ExecuteActionsEmail{},
		&gokeycloak.Group{},
		&gokeycloak.GroupsCount{},
		&gokeycloak.GetGroupsParams{},
		&gokeycloak.CompositesRepresentation{},
		&gokeycloak.Role{},
		&gokeycloak.GetRoleParams{},
		&gokeycloak.ClientMappingsRepresentation{},
		&gokeycloak.MappingsRepresentation{},
		&gokeycloak.ClientScope{},
		&gokeycloak.ClientScopeAttributes{},
		&gokeycloak.ProtocolMappers{},
		&gokeycloak.ProtocolMappersConfig{},
		&gokeycloak.Client{},
		&gokeycloak.ResourceServerRepresentation{},
		&gokeycloak.RoleDefinition{},
		&gokeycloak.PolicyRepresentation{},
		&gokeycloak.RolePolicyRepresentation{},
		&gokeycloak.JSPolicyRepresentation{},
		&gokeycloak.ClientPolicyRepresentation{},
		&gokeycloak.TimePolicyRepresentation{},
		&gokeycloak.UserPolicyRepresentation{},
		&gokeycloak.AggregatedPolicyRepresentation{},
		&gokeycloak.GroupPolicyRepresentation{},
		&gokeycloak.GroupDefinition{},
		&gokeycloak.ResourceRepresentation{},
		&gokeycloak.ResourceOwnerRepresentation{},
		&gokeycloak.ScopeRepresentation{},
		&gokeycloak.ProtocolMapperRepresentation{},
		&gokeycloak.UserInfoAddress{},
		&gokeycloak.UserInfo{},
		&gokeycloak.RolesRepresentation{},
		&gokeycloak.RealmRepresentation{},
		&gokeycloak.MultiValuedHashMap{},
		&gokeycloak.TokenOptions{},
		&gokeycloak.UserSessionRepresentation{},
		&gokeycloak.SystemInfoRepresentation{},
		&gokeycloak.MemoryInfoRepresentation{},
		&gokeycloak.ServerInfoRepresentation{},
		&gokeycloak.FederatedIdentityRepresentation{},
		&gokeycloak.IdentityProviderRepresentation{},
		&gokeycloak.GetResourceParams{},
		&gokeycloak.GetScopeParams{},
		&gokeycloak.GetPolicyParams{},
		&gokeycloak.GetPermissionParams{},
		&gokeycloak.GetUsersByRoleParams{},
		&gokeycloak.PermissionRepresentation{},
		&gokeycloak.CreatePermissionTicketParams{},
		&gokeycloak.PermissionTicketDescriptionRepresentation{},
		&gokeycloak.AccessRepresentation{},
		&gokeycloak.PermissionTicketResponseRepresentation{},
		&gokeycloak.PermissionTicketRepresentation{},
		&gokeycloak.PermissionTicketPermissionRepresentation{},
		&gokeycloak.PermissionGrantParams{},
		&gokeycloak.PermissionGrantResponseRepresentation{},
		&gokeycloak.GetUserPermissionParams{},
		&gokeycloak.ResourcePolicyRepresentation{},
		&gokeycloak.GetResourcePoliciesParams{},
		&gokeycloak.CredentialRepresentation{},
		&gokeycloak.GetUsersParams{},
		&gokeycloak.GetComponentsParams{},
		&gokeycloak.GetClientsParams{},
		&gokeycloak.RequestingPartyTokenOptions{},
		&gokeycloak.RequestingPartyPermission{},
	}

	for _, custom := range customs {
		assert.Equal(t, "{}", custom.String())
	}
}
