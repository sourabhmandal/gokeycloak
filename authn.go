package gocloak

import (
	"context"
	"io"

	"github.com/Nerzal/gocloak/v13/pkg/jwx"
	"github.com/golang-jwt/jwt/v4"
	"github.com/segmentio/ksuid"
)

// LoginAdmin performs a login with Admin client
func (g *GoCloak) LoginAdmin(ctx context.Context, username, password, realm string) (*JWT, error) {
	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:  StringP(adminClientID),
		GrantType: StringP("password"),
		Username:  &username,
		Password:  &password,
	})
}


// LoginClient performs a login with client credentials
func (g *GoCloak) LoginClient(ctx context.Context, clientID, clientSecret, realm string) (*JWT, error) {
	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("client_credentials"),
	})
} 

// LoginClientTokenExchange will exchange the presented token for a user's token
// Requires Token-Exchange is enabled: https://www.keycloak.org/docs/latest/securing_apps/index.html#_token-exchange
func (g *GoCloak) LoginClientTokenExchange(ctx context.Context, clientID, token, clientSecret, realm, targetClient, userID string) (*JWT, error) {
	tokenOptions := TokenOptions{
		ClientID:           &clientID,
		ClientSecret:       &clientSecret,
		GrantType:          StringP("urn:ietf:params:oauth:grant-type:token-exchange"),
		SubjectToken:       &token,
		RequestedTokenType: StringP("urn:ietf:params:oauth:token-type:refresh_token"),
		Audience:           &targetClient,
	}
	if userID != "" {
		tokenOptions.RequestedSubject = &userID
	}
	return g.GetToken(ctx, realm, tokenOptions)
}

// LoginClientSignedJWT performs a login with client credentials and signed jwt claims
func (g *GoCloak) LoginClientSignedJWT(
	ctx context.Context,
	clientID,
	realm string,
	key interface{},
	signedMethod jwt.SigningMethod,
	expiresAt *jwt.NumericDate,
) (*JWT, error) {
	claims := jwt.RegisteredClaims{
		ExpiresAt: expiresAt,
		Issuer:    clientID,
		Subject:   clientID,
		ID:        ksuid.New().String(),
		Audience: jwt.ClaimStrings{
			g.getRealmURL(realm),
		},
	}
	assertion, err := jwx.SignClaims(claims, key, signedMethod)
	if err != nil {
		return nil, err
	}

	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:            &clientID,
		GrantType:           StringP("client_credentials"),
		ClientAssertionType: StringP("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
		ClientAssertion:     &assertion,
	})
}

// Login performs a login with user credentials and a client
func (g *GoCloak) Login(ctx context.Context, clientID, clientSecret, realm, username, password string) (*JWT, error) {
	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("password"),
		Username:     &username,
		Password:     &password,
		Scope:        StringP("openid"),
	})
}

// LoginOtp performs a login with user credentials and otp token
func (g *GoCloak) LoginOtp(ctx context.Context, clientID, clientSecret, realm, username, password, totp string) (*JWT, error) {
	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("password"),
		Username:     &username,
		Password:     &password,
		Totp:         &totp,
	})
}


// GetAuthenticationFlows get all authentication flows from a realm
func (g *GoCloak) GetAuthenticationFlows(ctx context.Context, token, realm string) ([]*AuthenticationFlowRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result []*AuthenticationFlowRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "flows"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

// GetAuthenticationFlow get an authentication flow with the given ID
func (g *GoCloak) GetAuthenticationFlow(ctx context.Context, token, realm string, authenticationFlowID string) (*AuthenticationFlowRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result *AuthenticationFlowRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "flows", authenticationFlowID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

// CreateAuthenticationFlow creates a new Authentication flow in a realm
func (g *GoCloak) CreateAuthenticationFlow(ctx context.Context, token, realm string, flow AuthenticationFlowRepresentation) error {
	const errMessage = "could not create authentication flows"
	var result []*AuthenticationFlowRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).SetBody(flow).
		Post(g.getAdminRealmURL(realm, "authentication", "flows"))

	return checkForError(resp, err, errMessage)
}

// UpdateAuthenticationFlow a given Authentication Flow
func (g *GoCloak) UpdateAuthenticationFlow(ctx context.Context, token, realm string, flow AuthenticationFlowRepresentation, authenticationFlowID string) (*AuthenticationFlowRepresentation, error) {
	const errMessage = "could not create authentication flows"
	var result *AuthenticationFlowRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).SetBody(flow).
		Put(g.getAdminRealmURL(realm, "authentication", "flows", authenticationFlowID))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

// DeleteAuthenticationFlow deletes a flow in a realm with the given ID
func (g *GoCloak) DeleteAuthenticationFlow(ctx context.Context, token, realm, flowID string) error {
	const errMessage = "could not delete authentication flows"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "authentication", "flows", flowID))

	return checkForError(resp, err, errMessage)
}

// GetAuthenticationExecutions retrieves all executions of a given flow
func (g *GoCloak) GetAuthenticationExecutions(ctx context.Context, token, realm, flow string) ([]*ModifyAuthenticationExecutionRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result []*ModifyAuthenticationExecutionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "flows", flow, "executions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

// CreateAuthenticationExecution creates a new execution for the given flow name in the given realm
func (g *GoCloak) CreateAuthenticationExecution(ctx context.Context, token, realm, flow string, execution CreateAuthenticationExecutionRepresentation) error {
	const errMessage = "could not create authentication execution"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).SetBody(execution).
		Post(g.getAdminRealmURL(realm, "authentication", "flows", flow, "executions", "execution"))

	return checkForError(resp, err, errMessage)
}

// UpdateAuthenticationExecution updates an authentication execution for the given flow in the given realm
func (g *GoCloak) UpdateAuthenticationExecution(ctx context.Context, token, realm, flow string, execution ModifyAuthenticationExecutionRepresentation) error {
	const errMessage = "could not update authentication execution"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).SetBody(execution).
		Put(g.getAdminRealmURL(realm, "authentication", "flows", flow, "executions"))

	return checkForError(resp, err, errMessage)
}

// DeleteAuthenticationExecution delete a single execution with the given ID
func (g *GoCloak) DeleteAuthenticationExecution(ctx context.Context, token, realm, executionID string) error {
	const errMessage = "could not delete authentication execution"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "authentication", "executions", executionID))

	return checkForError(resp, err, errMessage)
}

// CreateAuthenticationExecutionFlow creates a new execution for the given flow name in the given realm
func (g *GoCloak) CreateAuthenticationExecutionFlow(ctx context.Context, token, realm, flow string, executionFlow CreateAuthenticationExecutionFlowRepresentation) error {
	const errMessage = "could not create authentication execution flow"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).SetBody(executionFlow).
		Post(g.getAdminRealmURL(realm, "authentication", "flows", flow, "executions", "flow"))

	return checkForError(resp, err, errMessage)
}



// ------------------
// Identity Providers
// ------------------

// CreateIdentityProvider creates an identity provider in a realm
func (g *GoCloak) CreateIdentityProvider(ctx context.Context, token string, realm string, providerRep IdentityProviderRepresentation) (string, error) {
	const errMessage = "could not create identity provider"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(providerRep).
		Post(g.getAdminRealmURL(realm, "identity-provider", "instances"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// GetIdentityProviders returns list of identity providers in a realm
func (g *GoCloak) GetIdentityProviders(ctx context.Context, token, realm string) ([]*IdentityProviderRepresentation, error) {
	const errMessage = "could not get identity providers"

	var result []*IdentityProviderRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "identity-provider", "instances"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetIdentityProvider gets the identity provider in a realm
func (g *GoCloak) GetIdentityProvider(ctx context.Context, token, realm, alias string) (*IdentityProviderRepresentation, error) {
	const errMessage = "could not get identity provider"

	var result IdentityProviderRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateIdentityProvider updates the identity provider in a realm
func (g *GoCloak) UpdateIdentityProvider(ctx context.Context, token, realm, alias string, providerRep IdentityProviderRepresentation) error {
	const errMessage = "could not update identity provider"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(providerRep).
		Put(g.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	return checkForError(resp, err, errMessage)
}

// DeleteIdentityProvider deletes the identity provider in a realm
func (g *GoCloak) DeleteIdentityProvider(ctx context.Context, token, realm, alias string) error {
	const errMessage = "could not delete identity provider"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	return checkForError(resp, err, errMessage)
}

// ExportIDPPublicBrokerConfig exports the broker config for a given alias
func (g *GoCloak) ExportIDPPublicBrokerConfig(ctx context.Context, token, realm, alias string) (*string, error) {
	const errMessage = "could not get public identity provider configuration"

	resp, err := g.GetRequestWithBearerAuthXMLHeader(ctx, token).
		Get(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "export"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	result := resp.String()
	return &result, nil
}

// ImportIdentityProviderConfig parses and returns the identity provider config at a given URL
func (g *GoCloak) ImportIdentityProviderConfig(ctx context.Context, token, realm, fromURL, providerID string) (map[string]string, error) {
	const errMessage = "could not import config"

	result := make(map[string]string)
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(map[string]string{
			"fromUrl":    fromURL,
			"providerId": providerID,
		}).
		Post(g.getAdminRealmURL(realm, "identity-provider", "import-config"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// ImportIdentityProviderConfigFromFile parses and returns the identity provider config from a given file
func (g *GoCloak) ImportIdentityProviderConfigFromFile(ctx context.Context, token, realm, providerID, fileName string, fileBody io.Reader) (map[string]string, error) {
	const errMessage = "could not import config"

	result := make(map[string]string)
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetFileReader("file", fileName, fileBody).
		SetFormData(map[string]string{
			"providerId": providerID,
		}).
		Post(g.getAdminRealmURL(realm, "identity-provider", "import-config"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateIdentityProviderMapper creates an instance of an identity provider mapper associated with the given alias
func (g *GoCloak) CreateIdentityProviderMapper(ctx context.Context, token, realm, alias string, mapper IdentityProviderMapper) (string, error) {
	const errMessage = "could not create mapper for identity provider"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Post(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// GetIdentityProviderMapper gets the mapper by id for the given identity provider alias in a realm
func (g *GoCloak) GetIdentityProviderMapper(ctx context.Context, token string, realm string, alias string, mapperID string) (*IdentityProviderMapper, error) {
	const errMessage = "could not get identity provider mapper"

	result := IdentityProviderMapper{}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", mapperID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteIdentityProviderMapper deletes an instance of an identity provider mapper associated with the given alias and mapper ID
func (g *GoCloak) DeleteIdentityProviderMapper(ctx context.Context, token, realm, alias, mapperID string) error {
	const errMessage = "could not delete mapper for identity provider"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", mapperID))

	return checkForError(resp, err, errMessage)
}

// GetIdentityProviderMappers returns list of mappers associated with an identity provider
func (g *GoCloak) GetIdentityProviderMappers(ctx context.Context, token, realm, alias string) ([]*IdentityProviderMapper, error) {
	const errMessage = "could not get identity provider mappers"

	var result []*IdentityProviderMapper
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetIdentityProviderMapperByID gets the mapper of an identity provider
func (g *GoCloak) GetIdentityProviderMapperByID(ctx context.Context, token, realm, alias, mapperID string) (*IdentityProviderMapper, error) {
	const errMessage = "could not get identity provider mappers"

	var result IdentityProviderMapper
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", mapperID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateIdentityProviderMapper updates mapper of an identity provider
func (g *GoCloak) UpdateIdentityProviderMapper(ctx context.Context, token, realm, alias string, mapper IdentityProviderMapper) error {
	const errMessage = "could not update identity provider mapper"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Put(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", PString(mapper.ID)))

	return checkForError(resp, err, errMessage)
}
