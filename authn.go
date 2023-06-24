package gokeycloak

import (
	"context"
	"io"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/segmentio/ksuid"
	"github.com/zblocks/gokeycloak/pkg/jwx"
)

// LoginAdmin performs a login with Admin client
func (g *GoKeycloak) LoginAdmin(ctx context.Context, username, password, realm string) (int, *JWT, error) {
	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:  StringP(adminClientID),
		GrantType: StringP("password"),
		Username:  &username,
		Password:  &password,
	})
}

// LoginClient performs a login with client credentials
func (g *GoKeycloak) LoginClient(ctx context.Context, clientID, clientSecret, realm string) (int, *JWT, error) {
	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("client_credentials"),
	})
}

// LoginClientTokenExchange will exchange the presented token for a user's token
// Requires Token-Exchange is enabled: https://www.keycloak.org/docs/latest/securing_apps/index.html#_token-exchange
func (g *GoKeycloak) LoginClientTokenExchange(ctx context.Context, clientID, token, clientSecret, realm, targetClient, userID string) (int, *JWT, error) {
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
func (g *GoKeycloak) LoginClientSignedJWT(
	ctx context.Context,
	clientID,
	realm string,
	key interface{},
	signedMethod jwt.SigningMethod,
	expiresAt *jwt.NumericDate,
) (int, *JWT, error) {
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
		return http.StatusInternalServerError, nil, err
	}

	return g.GetToken(ctx, realm, TokenOptions{
		ClientID:            &clientID,
		GrantType:           StringP("client_credentials"),
		ClientAssertionType: StringP("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
		ClientAssertion:     &assertion,
	})
}

// Login performs a login with user credentials and a client
func (g *GoKeycloak) Login(ctx context.Context, clientID, clientSecret, realm, username, password string) (int, *JWT, error) {
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
func (g *GoKeycloak) LoginOtp(ctx context.Context, clientID, clientSecret, realm, username, password, totp string) (int, *JWT, error) {
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
func (g *GoKeycloak) GetAuthenticationFlows(ctx context.Context, token, realm string) (int, []*AuthenticationFlowRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result []*AuthenticationFlowRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "flows"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}
	return resp.StatusCode(), result, nil
}

// GetAuthenticationFlow get an authentication flow with the given ID
func (g *GoKeycloak) GetAuthenticationFlow(ctx context.Context, token, realm string, authenticationFlowID string) (int, *AuthenticationFlowRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result *AuthenticationFlowRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "flows", authenticationFlowID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}
	return resp.StatusCode(), result, nil
}

// CreateAuthenticationFlow creates a new Authentication flow in a realm
func (g *GoKeycloak) CreateAuthenticationFlow(ctx context.Context, token, realm string, flow AuthenticationFlowRepresentation) (int, error) {
	const errMessage = "could not create authentication flows"
	var result []*AuthenticationFlowRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).SetBody(flow).
		Post(g.getAdminRealmURL(realm, "authentication", "flows"))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// UpdateAuthenticationFlow a given Authentication Flow
func (g *GoKeycloak) UpdateAuthenticationFlow(ctx context.Context, token, realm string, flow AuthenticationFlowRepresentation, authenticationFlowID string) (int, *AuthenticationFlowRepresentation, error) {
	const errMessage = "could not create authentication flows"
	var result *AuthenticationFlowRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).SetBody(flow).
		Put(g.getAdminRealmURL(realm, "authentication", "flows", authenticationFlowID))

	if err = checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}
	return resp.StatusCode(), result, nil
}

// DeleteAuthenticationFlow deletes a flow in a realm with the given ID
func (g *GoKeycloak) DeleteAuthenticationFlow(ctx context.Context, token, realm, flowID string) (int, error) {
	const errMessage = "could not delete authentication flows"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "authentication", "flows", flowID))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// GetAuthenticationExecutions retrieves all executions of a given flow
func (g *GoKeycloak) GetAuthenticationExecutions(ctx context.Context, token, realm, flow string) (int, []*ModifyAuthenticationExecutionRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result []*ModifyAuthenticationExecutionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "flows", flow, "executions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}
	return resp.StatusCode(), result, nil
}

// CreateAuthenticationExecution creates a new execution for the given flow name in the given realm
func (g *GoKeycloak) CreateAuthenticationExecution(ctx context.Context, token, realm, flow string, execution CreateAuthenticationExecutionRepresentation) (int, error) {
	const errMessage = "could not create authentication execution"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).SetBody(execution).
		Post(g.getAdminRealmURL(realm, "authentication", "flows", flow, "executions", "execution"))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// UpdateAuthenticationExecution updates an authentication execution for the given flow in the given realm
func (g *GoKeycloak) UpdateAuthenticationExecution(ctx context.Context, token, realm, flow string, execution ModifyAuthenticationExecutionRepresentation) (int, error) {
	const errMessage = "could not update authentication execution"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).SetBody(execution).
		Put(g.getAdminRealmURL(realm, "authentication", "flows", flow, "executions"))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// DeleteAuthenticationExecution delete a single execution with the given ID
func (g *GoKeycloak) DeleteAuthenticationExecution(ctx context.Context, token, realm, executionID string) (int, error) {
	const errMessage = "could not delete authentication execution"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "authentication", "executions", executionID))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// CreateAuthenticationExecutionFlow creates a new execution for the given flow name in the given realm
func (g *GoKeycloak) CreateAuthenticationExecutionFlow(ctx context.Context, token, realm, flow string, executionFlow CreateAuthenticationExecutionFlowRepresentation) (int, error) {
	const errMessage = "could not create authentication execution flow"
	resp, err := g.GetRequestWithBearerAuth(ctx, token).SetBody(executionFlow).
		Post(g.getAdminRealmURL(realm, "authentication", "flows", flow, "executions", "flow"))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// ------------------
// Identity Providers
// ------------------

// CreateIdentityProvider creates an identity provider in a realm
func (g *GoKeycloak) CreateIdentityProvider(ctx context.Context, token string, realm string, providerRep IdentityProviderRepresentation) (int, string, error) {
	const errMessage = "could not create identity provider"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(providerRep).
		Post(g.getAdminRealmURL(realm, "identity-provider", "instances"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), "", err
	}

	return resp.StatusCode(), getID(resp), nil
}

// GetIdentityProviders returns list of identity providers in a realm
func (g *GoKeycloak) GetIdentityProviders(ctx context.Context, token, realm string) (int, []*IdentityProviderRepresentation, error) {
	const errMessage = "could not get identity providers"

	var result []*IdentityProviderRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "identity-provider", "instances"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), result, nil
}

// GetIdentityProvider gets the identity provider in a realm
func (g *GoKeycloak) GetIdentityProvider(ctx context.Context, token, realm, alias string) (int, *IdentityProviderRepresentation, error) {
	const errMessage = "could not get identity provider"

	var result IdentityProviderRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

// UpdateIdentityProvider updates the identity provider in a realm
func (g *GoKeycloak) UpdateIdentityProvider(ctx context.Context, token, realm, alias string, providerRep IdentityProviderRepresentation) (int, error) {
	const errMessage = "could not update identity provider"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(providerRep).
		Put(g.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// DeleteIdentityProvider deletes the identity provider in a realm
func (g *GoKeycloak) DeleteIdentityProvider(ctx context.Context, token, realm, alias string) (int, error) {
	const errMessage = "could not delete identity provider"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// ExportIDPPublicBrokerConfig exports the broker config for a given alias
func (g *GoKeycloak) ExportIDPPublicBrokerConfig(ctx context.Context, token, realm, alias string) (int, *string, error) {
	const errMessage = "could not get public identity provider configuration"

	resp, err := g.GetRequestWithBearerAuthXMLHeader(ctx, token).
		Get(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "export"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	result := resp.String()
	return resp.StatusCode(), &result, nil
}

// ImportIdentityProviderConfig parses and returns the identity provider config at a given URL
func (g *GoKeycloak) ImportIdentityProviderConfig(ctx context.Context, token, realm, fromURL, providerID string) (int, map[string]string, error) {
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
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), result, nil
}

// ImportIdentityProviderConfigFromFile parses and returns the identity provider config from a given file
func (g *GoKeycloak) ImportIdentityProviderConfigFromFile(ctx context.Context, token, realm, providerID, fileName string, fileBody io.Reader) (int, map[string]string, error) {
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
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), result, nil
}

// CreateIdentityProviderMapper creates an instance of an identity provider mapper associated with the given alias
func (g *GoKeycloak) CreateIdentityProviderMapper(ctx context.Context, token, realm, alias string, mapper IdentityProviderMapper) (int, string, error) {
	const errMessage = "could not create mapper for identity provider"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Post(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), "", err
	}

	return resp.StatusCode(), getID(resp), nil
}

// GetIdentityProviderMapper gets the mapper by id for the given identity provider alias in a realm
func (g *GoKeycloak) GetIdentityProviderMapper(ctx context.Context, token string, realm string, alias string, mapperID string) (int, *IdentityProviderMapper, error) {
	const errMessage = "could not get identity provider mapper"

	result := IdentityProviderMapper{}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", mapperID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

// DeleteIdentityProviderMapper deletes an instance of an identity provider mapper associated with the given alias and mapper ID
func (g *GoKeycloak) DeleteIdentityProviderMapper(ctx context.Context, token, realm, alias, mapperID string) (int, error) {
	const errMessage = "could not delete mapper for identity provider"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", mapperID))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}

// GetIdentityProviderMappers returns list of mappers associated with an identity provider
func (g *GoKeycloak) GetIdentityProviderMappers(ctx context.Context, token, realm, alias string) (int, []*IdentityProviderMapper, error) {
	const errMessage = "could not get identity provider mappers"

	var result []*IdentityProviderMapper
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), result, nil
}

// GetIdentityProviderMapperByID gets the mapper of an identity provider
func (g *GoKeycloak) GetIdentityProviderMapperByID(ctx context.Context, token, realm, alias, mapperID string) (int, *IdentityProviderMapper, error) {
	const errMessage = "could not get identity provider mappers"

	var result IdentityProviderMapper
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", mapperID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

// UpdateIdentityProviderMapper updates mapper of an identity provider
func (g *GoKeycloak) UpdateIdentityProviderMapper(ctx context.Context, token, realm, alias string, mapper IdentityProviderMapper) (int, error) {
	const errMessage = "could not update identity provider mapper"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Put(g.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", PString(mapper.ID)))

	return resp.StatusCode(), checkForError(resp, err, errMessage)
}
