// package gokeycloak is a golang keycloak adaptor.
package gokeycloak

import (
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
)

// GoCloak provides functionalities to talk to Keycloak.
type GoKeycloak struct {
	basePath    string
	certsCache  sync.Map
	certsLock   sync.Mutex
	restyClient *resty.Client
	Config      struct {
		CertsInvalidateTime time.Duration
		authAdminRealms     string
		authRealms          string
		openIDConnect       string
		attackDetection     string
	}
}

const (
	adminClientID string = "admin-cli"
	urlSeparator  string = "/"
)

func makeURL(path ...string) string {
	return strings.Join(path, urlSeparator)
}

// GetRequest returns a request for calling endpoints.
func (g *GoKeycloak) GetRequest(ctx context.Context) *resty.Request {
	var err HTTPErrorResponse
	return injectTracingHeaders(
		ctx, g.restyClient.R().
			SetContext(ctx).
			SetError(&err),
	)
}

// GetRequestWithBearerAuthNoCache returns a JSON base request configured with an auth token and no-cache header.
func (g *GoKeycloak) GetRequestWithBearerAuthNoCache(ctx context.Context, token string) *resty.Request {
	return g.GetRequest(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json").
		SetHeader("Cache-Control", "no-cache")
}

// GetRequestWithBearerAuth returns a JSON base request configured with an auth token.
func (g *GoKeycloak) GetRequestWithBearerAuth(ctx context.Context, token string) *resty.Request {
	return g.GetRequest(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json")
}

// GetRequestWithBearerAuthXMLHeader returns an XML base request configured with an auth token.
func (g *GoKeycloak) GetRequestWithBearerAuthXMLHeader(ctx context.Context, token string) *resty.Request {
	return g.GetRequest(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/xml;charset=UTF-8")
}

// GetRequestWithBasicAuth returns a form data base request configured with basic auth.
func (g *GoKeycloak) GetRequestWithBasicAuth(ctx context.Context, clientID, clientSecret string) *resty.Request {
	req := g.GetRequest(ctx).
		SetHeader("Content-Type", "application/x-www-form-urlencoded")
	// Public client doesn't require Basic Auth
	if len(clientID) > 0 && len(clientSecret) > 0 {
		httpBasicAuth := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
		req.SetHeader("Authorization", "Basic "+httpBasicAuth)
	}

	return req
}



func getID(resp *resty.Response) string {
	header := resp.Header().Get("Location")
	splittedPath := strings.Split(header, urlSeparator)

	return splittedPath[len(splittedPath)-1]
}

func findUsedKey(usedKeyID string, keys []CertResponseKey) *CertResponseKey {
	for _, key := range keys {
		if *(key.Kid) == usedKeyID {
			return &key
		}
	}

	return nil
}

func injectTracingHeaders(ctx context.Context, req *resty.Request) *resty.Request {
	// look for span in context, do nothing if span is not found
	span := opentracing.SpanFromContext(ctx)
	if span == nil {
		return req
	}

	// look for tracer in context, use global tracer if not found
	tracer, ok := ctx.Value(tracerContextKey).(opentracing.Tracer)
	if !ok || tracer == nil {
		tracer = opentracing.GlobalTracer()
	}

	// inject tracing header into request
	err := tracer.Inject(span.Context(), opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(req.Header))
	if err != nil {
		return req
	}

	return req
}

// ===============
// Keycloak client
// ===============

// NewClient creates a new Client
func NewClient(basePath string, options ...func(*GoKeycloak)) *GoKeycloak {
	c := GoKeycloak{
		basePath:    strings.TrimRight(basePath, urlSeparator),
		restyClient: resty.New(),
	}

	c.Config.CertsInvalidateTime = 10 * time.Minute
	c.Config.authAdminRealms = makeURL("admin", "realms")
	c.Config.authRealms = makeURL("realms")
	c.Config.openIDConnect = makeURL("protocol", "openid-connect")
	c.Config.attackDetection = makeURL("attack-detection", "brute-force")

	for _, option := range options {
		option(&c)
	}

	return &c
}

// RestyClient returns the internal resty g.
// This can be used to configure the g.
func (g *GoKeycloak) RestyClient() *resty.Client {
	return g.restyClient
}

// SetRestyClient overwrites the internal resty g.
func (g *GoKeycloak) SetRestyClient(restyClient *resty.Client) {
	g.restyClient = restyClient
}

// ==== Functional Options ===
// SetCertCacheInvalidationTime sets the logout
func SetCertCacheInvalidationTime(duration time.Duration) func(g *GoKeycloak) {
	return func(g *GoKeycloak) {
		g.Config.CertsInvalidateTime = duration
	}
}

// RevokeUserConsents revokes the given user consent.
func (g *GoKeycloak) RevokeUserConsents(ctx context.Context, accessToken, realm, userID, clientID string) error {
	const errMessage = "could not revoke consents"

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		Delete(g.getAdminRealmURL(realm, "users", userID, "consents", clientID))

	return checkForError(resp, err, errMessage)
}

// LogoutUserSession logs out a single sessions of a user given a session id
func (g *GoKeycloak) LogoutUserSession(ctx context.Context, accessToken, realm, session string) error {
	const errMessage = "could not logout"

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		Delete(g.getAdminRealmURL(realm, "sessions", session))

	return checkForError(resp, err, errMessage)
}

// ExecuteActionsEmail executes an actions email
func (g *GoKeycloak) ExecuteActionsEmail(ctx context.Context, token, realm string, params ExecuteActionsEmail) error {
	const errMessage = "could not execute actions email"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return errors.Wrap(err, errMessage)
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(params.Actions).
		SetQueryParams(queryParams).
		Put(g.getAdminRealmURL(realm, "users", *(params.UserID), "execute-actions-email"))

	return checkForError(resp, err, errMessage)
}

// CreateComponent creates the given component.
func (g *GoKeycloak) CreateComponent(ctx context.Context, token, realm string, component Component) (string, error) {
	const errMessage = "could not create component"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(component).
		Post(g.getAdminRealmURL(realm, "components"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// CreateClient creates the given g.
func (g *GoKeycloak) CreateClient(ctx context.Context, clientInitialAccessToken, realm string, newClient Client) (CreateClientResponse, error) {
	const errMessage = "could not create client"

	var result CreateClientResponse

	// create a client
	resp, err := g.GetRequestWithBearerAuth(ctx, clientInitialAccessToken).
		SetBody(newClient).SetResult(&result).
		Post(g.getRealmURL(realm, "clients-registrations", "openid-connect"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return result, err
	}

	return result, nil
}

// CreateClientRepresentation creates a new client representation
func (g *GoKeycloak) CreateClientRepresentation(ctx context.Context, token, realm string, newClient Client) (*Client, error) {
	const errMessage = "could not create client representation"

	var result Client

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(newClient).
		Post(g.getRealmURL(realm, "clients-registrations", "default"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// CreateClientRole creates a new role for a client
func (g *GoKeycloak) CreateClientRole(ctx context.Context, token, realm, idOfClient string, role Role) (string, error) {
	const errMessage = "could not create client role"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// CreateClientScope creates a new client scope
func (g *GoKeycloak) CreateClientScope(ctx context.Context, token, realm string, scope ClientScope) (string, error) {
	const errMessage = "could not create client scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Post(g.getAdminRealmURL(realm, "client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// CreateClientScopeProtocolMapper creates a new protocolMapper under the given client scope
func (g *GoKeycloak) CreateClientScopeProtocolMapper(ctx context.Context, token, realm, scopeID string, protocolMapper ProtocolMappers) (string, error) {
	const errMessage = "could not create client scope protocol mapper"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(protocolMapper).
		Post(g.getAdminRealmURL(realm, "client-scopes", scopeID, "protocol-mappers", "models"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// UpdateClient updates the given Client
func (g *GoKeycloak) UpdateClient(ctx context.Context, token, realm string, updatedClient Client) error {
	const errMessage = "could not update client"

	if NilOrEmpty(updatedClient.ID) {
		return errors.Wrap(errors.New("ID of a client required"), errMessage)
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(updatedClient).
		Put(g.getAdminRealmURL(realm, "clients", PString(updatedClient.ID)))

	return checkForError(resp, err, errMessage)
}

// UpdateClientRepresentation updates the given client representation
func (g *GoKeycloak) UpdateClientRepresentation(ctx context.Context, accessToken, realm string, updatedClient Client) (*Client, error) {
	const errMessage = "could not update client representation"

	if NilOrEmpty(updatedClient.ID) {
		return nil, errors.Wrap(errors.New("ID of a client required"), errMessage)
	}

	var result Client

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		SetBody(updatedClient).
		Put(g.getRealmURL(realm, "clients-registrations", "default", PString(updatedClient.ClientID)))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateRole updates the given role.
func (g *GoKeycloak) UpdateRole(ctx context.Context, token, realm, idOfClient string, role Role) error {
	const errMessage = "could not update role"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "roles", PString(role.Name)))

	return checkForError(resp, err, errMessage)
}

// UpdateClientScope updates the given client scope.
func (g *GoKeycloak) UpdateClientScope(ctx context.Context, token, realm string, scope ClientScope) error {
	const errMessage = "could not update client scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Put(g.getAdminRealmURL(realm, "client-scopes", PString(scope.ID)))

	return checkForError(resp, err, errMessage)
}

// UpdateClientScopeProtocolMapper updates the given protocol mapper for a client scope
func (g *GoKeycloak) UpdateClientScopeProtocolMapper(ctx context.Context, token, realm, scopeID string, protocolMapper ProtocolMappers) error {
	const errMessage = "could not update client scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(protocolMapper).
		Put(g.getAdminRealmURL(realm, "client-scopes", scopeID, "protocol-mappers", "models", PString(protocolMapper.ID)))

	return checkForError(resp, err, errMessage)
}

// DeleteClient deletes a given client
func (g *GoKeycloak) DeleteClient(ctx context.Context, token, realm, idOfClient string) error {
	const errMessage = "could not delete client"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// DeleteComponent deletes the component with the given id.
func (g *GoKeycloak) DeleteComponent(ctx context.Context, token, realm, componentID string) error {
	const errMessage = "could not delete component"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "components", componentID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRepresentation deletes a given client representation.
func (g *GoKeycloak) DeleteClientRepresentation(ctx context.Context, accessToken, realm, clientID string) error {
	const errMessage = "could not delete client representation"

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		Delete(g.getRealmURL(realm, "clients-registrations", "default", clientID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRole deletes a given role.
func (g *GoKeycloak) DeleteClientRole(ctx context.Context, token, realm, idOfClient, roleName string) error {
	const errMessage = "could not delete client role"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "roles", roleName))

	return checkForError(resp, err, errMessage)
}

// DeleteClientScope deletes the scope with the given id.
func (g *GoKeycloak) DeleteClientScope(ctx context.Context, token, realm, scopeID string) error {
	const errMessage = "could not delete client scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientScopeProtocolMapper deletes the given protocol mapper from the client scope
func (g *GoKeycloak) DeleteClientScopeProtocolMapper(ctx context.Context, token, realm, scopeID, protocolMapperID string) error {
	const errMessage = "could not delete client scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "client-scopes", scopeID, "protocol-mappers", "models", protocolMapperID))

	return checkForError(resp, err, errMessage)
}

// GetClient returns a client
func (g *GoKeycloak) GetClient(ctx context.Context, token, realm, idOfClient string) (*Client, error) {
	const errMessage = "could not get client"

	var result Client

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientRepresentation returns a client representation
func (g *GoKeycloak) GetClientRepresentation(ctx context.Context, accessToken, realm, clientID string) (*Client, error) {
	const errMessage = "could not get client representation"

	var result Client

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(g.getRealmURL(realm, "clients-registrations", "default", clientID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetAdapterConfiguration returns a adapter configuration
func (g *GoKeycloak) GetAdapterConfiguration(ctx context.Context, accessToken, realm, clientID string) (*AdapterConfiguration, error) {
	const errMessage = "could not get adapter configuration"

	var result AdapterConfiguration

	resp, err := g.GetRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(g.getRealmURL(realm, "clients-registrations", "install", clientID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientsDefaultScopes returns a list of the client's default scopes
func (g *GoKeycloak) GetClientsDefaultScopes(ctx context.Context, token, realm, idOfClient string) ([]*ClientScope, error) {
	const errMessage = "could not get clients default scopes"

	var result []*ClientScope

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "default-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddDefaultScopeToClient adds a client scope to the list of client's default scopes
func (g *GoKeycloak) AddDefaultScopeToClient(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not add default scope to client"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "default-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// RemoveDefaultScopeFromClient removes a client scope from the list of client's default scopes
func (g *GoKeycloak) RemoveDefaultScopeFromClient(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not remove default scope from client"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "default-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetClientsOptionalScopes returns a list of the client's optional scopes
func (g *GoKeycloak) GetClientsOptionalScopes(ctx context.Context, token, realm, idOfClient string) ([]*ClientScope, error) {
	const errMessage = "could not get clients optional scopes"

	var result []*ClientScope

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "optional-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddOptionalScopeToClient adds a client scope to the list of client's optional scopes
func (g *GoKeycloak) AddOptionalScopeToClient(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not add optional scope to client"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "optional-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// RemoveOptionalScopeFromClient deletes a client scope from the list of client's optional scopes
func (g *GoKeycloak) RemoveOptionalScopeFromClient(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not remove optional scope from client"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "optional-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetDefaultOptionalClientScopes returns a list of default realm optional scopes
func (g *GoKeycloak) GetDefaultOptionalClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error) {
	const errMessage = "could not get default optional client scopes"

	var result []*ClientScope

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "default-optional-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetDefaultDefaultClientScopes returns a list of default realm default scopes
func (g *GoKeycloak) GetDefaultDefaultClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error) {
	const errMessage = "could not get default client scopes"

	var result []*ClientScope

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "default-default-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScope returns a clientscope
func (g *GoKeycloak) GetClientScope(ctx context.Context, token, realm, scopeID string) (*ClientScope, error) {
	const errMessage = "could not get client scope"

	var result ClientScope

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "client-scopes", scopeID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientScopes returns all client scopes
func (g *GoKeycloak) GetClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error) {
	const errMessage = "could not get client scopes"

	var result []*ClientScope

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeProtocolMappers returns all protocol mappers of a client scope
func (g *GoKeycloak) GetClientScopeProtocolMappers(ctx context.Context, token, realm, scopeID string) ([]*ProtocolMappers, error) {
	const errMessage = "could not get client scope protocol mappers"

	var result []*ProtocolMappers

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "client-scopes", scopeID, "protocol-mappers", "models"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeProtocolMapper returns a protocol mapper of a client scope
func (g *GoKeycloak) GetClientScopeProtocolMapper(ctx context.Context, token, realm, scopeID, protocolMapperID string) (*ProtocolMappers, error) {
	const errMessage = "could not get client scope protocol mappers"

	var result *ProtocolMappers

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "client-scopes", scopeID, "protocol-mappers", "models", protocolMapperID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappings returns all scope mappings for the client
func (g *GoKeycloak) GetClientScopeMappings(ctx context.Context, token, realm, idOfClient string) (*MappingsRepresentation, error) {
	const errMessage = "could not get all scope mappings for the client"

	var result *MappingsRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappingsRealmRoles returns realm-level roles associated with the client’s scope
func (g *GoKeycloak) GetClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string) ([]*Role, error) {
	const errMessage = "could not get realm-level roles with the client’s scope"

	var result []*Role

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "realm"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappingsRealmRolesAvailable returns realm-level roles that are available to attach to this client’s scope
func (g *GoKeycloak) GetClientScopeMappingsRealmRolesAvailable(ctx context.Context, token, realm, idOfClient string) ([]*Role, error) {
	const errMessage = "could not get available realm-level roles with the client’s scope"

	var result []*Role

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "realm", "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateClientScopeMappingsRealmRoles create realm-level roles to the client’s scope
func (g *GoKeycloak) CreateClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string, roles []Role) error {
	const errMessage = "could not create realm-level roles to the client’s scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// DeleteClientScopeMappingsRealmRoles deletes realm-level roles from the client’s scope
func (g *GoKeycloak) DeleteClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string, roles []Role) error {
	const errMessage = "could not delete realm-level roles from the client’s scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// GetClientScopeMappingsClientRoles returns roles associated with a client’s scope
func (g *GoKeycloak) GetClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string) ([]*Role, error) {
	const errMessage = "could not get roles associated with a client’s scope"

	var result []*Role

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "clients", idOfSelectedClient))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappingsClientRolesAvailable returns available roles associated with a client’s scope
func (g *GoKeycloak) GetClientScopeMappingsClientRolesAvailable(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string) ([]*Role, error) {
	const errMessage = "could not get available roles associated with a client’s scope"

	var result []*Role

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "clients", idOfSelectedClient, "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateClientScopeMappingsClientRoles creates client-level roles from the client’s scope
func (g *GoKeycloak) CreateClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string, roles []Role) error {
	const errMessage = "could not create client-level roles from the client’s scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "clients", idOfSelectedClient))

	return checkForError(resp, err, errMessage)
}

// DeleteClientScopeMappingsClientRoles deletes client-level roles from the client’s scope
func (g *GoKeycloak) DeleteClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string, roles []Role) error {
	const errMessage = "could not delete client-level roles from the client’s scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "clients", idOfSelectedClient))

	return checkForError(resp, err, errMessage)
}

// GetClientSecret returns a client's secret
func (g *GoKeycloak) GetClientSecret(ctx context.Context, token, realm, idOfClient string) (*CredentialRepresentation, error) {
	const errMessage = "could not get client secret"

	var result CredentialRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "client-secret"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientServiceAccount retrieves the service account "user" for a client if enabled
func (g *GoKeycloak) GetClientServiceAccount(ctx context.Context, token, realm, idOfClient string) (*User, error) {
	const errMessage = "could not get client service account"

	var result User
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "service-account-user"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// RegenerateClientSecret triggers the creation of the new client secret.
func (g *GoKeycloak) RegenerateClientSecret(ctx context.Context, token, realm, idOfClient string) (*CredentialRepresentation, error) {
	const errMessage = "could not regenerate client secret"

	var result CredentialRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "client-secret"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientOfflineSessions returns offline sessions associated with the client
func (g *GoKeycloak) GetClientOfflineSessions(ctx context.Context, token, realm, idOfClient string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get client offline sessions"

	var res []*UserSessionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "offline-sessions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// GetClientUserSessions returns user sessions associated with the client
func (g *GoKeycloak) GetClientUserSessions(ctx context.Context, token, realm, idOfClient string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get client user sessions"

	var res []*UserSessionRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "user-sessions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// CreateClientProtocolMapper creates a protocol mapper in client scope
func (g *GoKeycloak) CreateClientProtocolMapper(ctx context.Context, token, realm, idOfClient string, mapper ProtocolMapperRepresentation) (string, error) {
	const errMessage = "could not create client protocol mapper"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Post(g.getAdminRealmURL(realm, "clients", idOfClient, "protocol-mappers", "models"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// UpdateClientProtocolMapper updates a protocol mapper in client scope
func (g *GoKeycloak) UpdateClientProtocolMapper(ctx context.Context, token, realm, idOfClient, mapperID string, mapper ProtocolMapperRepresentation) error {
	const errMessage = "could not update client protocol mapper"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Put(g.getAdminRealmURL(realm, "clients", idOfClient, "protocol-mappers", "models", mapperID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientProtocolMapper deletes a protocol mapper in client scope
func (g *GoKeycloak) DeleteClientProtocolMapper(ctx context.Context, token, realm, idOfClient, mapperID string) error {
	const errMessage = "could not delete client protocol mapper"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "clients", idOfClient, "protocol-mappers", "models", mapperID))

	return checkForError(resp, err, errMessage)
}

// GetKeyStoreConfig get keystoreconfig of the realm
func (g *GoKeycloak) GetKeyStoreConfig(ctx context.Context, token, realm string) (*KeyStoreConfig, error) {
	const errMessage = "could not get key store config"

	var result KeyStoreConfig
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "keys"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

func (g *GoKeycloak) getRoleMappings(ctx context.Context, token, realm, path, objectID string) (*MappingsRepresentation, error) {
	const errMessage = "could not get role mappings"

	var result MappingsRepresentation
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, path, objectID, "role-mappings"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRoleMappingByGroupID gets the role mappings by group
func (g *GoKeycloak) GetRoleMappingByGroupID(ctx context.Context, token, realm, groupID string) (*MappingsRepresentation, error) {
	return g.getRoleMappings(ctx, token, realm, "groups", groupID)
}

// GetRoleMappingByUserID gets the role mappings by user
func (g *GoKeycloak) GetRoleMappingByUserID(ctx context.Context, token, realm, userID string) (*MappingsRepresentation, error) {
	return g.getRoleMappings(ctx, token, realm, "users", userID)
}

// GetClientRoles get all roles for the given client in realm
func (g *GoKeycloak) GetClientRoles(ctx context.Context, token, realm, idOfClient string, params GetRoleParams) ([]*Role, error) {
	const errMessage = "could not get client roles"

	var result []*Role
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRoleByID gets role for the given client in realm using role ID
func (g *GoKeycloak) GetClientRoleByID(ctx context.Context, token, realm, roleID string) (*Role, error) {
	const errMessage = "could not get client role"

	var result Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "roles-by-id", roleID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientRolesByUserID returns all client roles assigned to the given user
func (g *GoKeycloak) GetClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*Role, error) {
	const errMessage = "could not client roles by user id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRolesByGroupID returns all client roles assigned to the given group
func (g *GoKeycloak) GetClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*Role, error) {
	const errMessage = "could not get client roles by group id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeClientRolesByRoleID returns all client composite roles associated with the given client role
func (g *GoKeycloak) GetCompositeClientRolesByRoleID(ctx context.Context, token, realm, idOfClient, roleID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by role id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "roles-by-id", roleID, "composites", "clients", idOfClient))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeClientRolesByUserID returns all client roles and composite roles assigned to the given user
func (g *GoKeycloak) GetCompositeClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by user id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient, "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableClientRolesByUserID returns all available client roles to the given user
func (g *GoKeycloak) GetAvailableClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient, "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableClientRolesByGroupID returns all available roles to the given group
func (g *GoKeycloak) GetAvailableClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient, "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeClientRolesByGroupID returns all client roles and composite roles assigned to the given group
func (g *GoKeycloak) GetCompositeClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by group id"

	var result []*Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient, "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRole get a role for the given client in a realm by role name
func (g *GoKeycloak) GetClientRole(ctx context.Context, token, realm, idOfClient, roleName string) (*Role, error) {
	const errMessage = "could not get client role"

	var result Role
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "clients", idOfClient, "roles", roleName))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClients gets all clients in realm
func (g *GoKeycloak) GetClients(ctx context.Context, token, realm string, params GetClientsParams) ([]*Client, error) {
	const errMessage = "could not get clients"

	var result []*Client
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.getAdminRealmURL(realm, "clients"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// UserAttributeContains checks if the given attribute value is set
func UserAttributeContains(attributes map[string][]string, attribute, value string) bool {
	for _, item := range attributes[attribute] {
		if item == value {
			return true
		}
	}
	return false
}

// ClearUserCache clears realm cache
func (g *GoKeycloak) ClearUserCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear user cache"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Post(g.getAdminRealmURL(realm, "clear-user-cache"))

	return checkForError(resp, err, errMessage)
}

// ClearKeysCache clears realm cache
func (g *GoKeycloak) ClearKeysCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear keys cache"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Post(g.getAdminRealmURL(realm, "clear-keys-cache"))

	return checkForError(resp, err, errMessage)
}

// AddClientRoleComposite adds roles as composite
func (g *GoKeycloak) AddClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error {
	const errMessage = "could not add client role composite"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(g.getAdminRealmURL(realm, "roles-by-id", roleID, "composites"))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRoleComposite deletes composites from a role
func (g *GoKeycloak) DeleteClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error {
	const errMessage = "could not delete client role composite"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(g.getAdminRealmURL(realm, "roles-by-id", roleID, "composites"))

	return checkForError(resp, err, errMessage)
}

// GetClientScopesScopeMappingsRealmRolesAvailable returns realm-level roles that are available to attach to this client scope
func (g *GoKeycloak) GetClientScopesScopeMappingsRealmRolesAvailable(ctx context.Context, token, realm, clientScopeID string) ([]*Role, error) {
	const errMessage = "could not get available realm-level roles with the client-scope"

	var result []*Role

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "client-scopes", clientScopeID, "scope-mappings", "realm", "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopesScopeMappingsRealmRoles returns roles associated with a client-scope
func (g *GoKeycloak) GetClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, clientScopeID string) ([]*Role, error) {
	const errMessage = "could not get realm-level roles with the client-scope"

	var result []*Role

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "client-scopes", clientScopeID, "scope-mappings", "realm"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteClientScopesScopeMappingsRealmRoles deletes realm-level roles from the client-scope
func (g *GoKeycloak) DeleteClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, clientScopeID string, roles []Role) error {
	const errMessage = "could not delete realm-level roles from the client-scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(g.getAdminRealmURL(realm, "client-scopes", clientScopeID, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// CreateClientScopesScopeMappingsRealmRoles creates realm-level roles to the client scope
func (g *GoKeycloak) CreateClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, clientScopeID string, roles []Role) error {
	const errMessage = "could not create realm-level roles to the client-scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(g.getAdminRealmURL(realm, "client-scopes", clientScopeID, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// RegisterRequiredAction creates a required action for a given realm
func (g *GoKeycloak) RegisterRequiredAction(ctx context.Context, token string, realm string, requiredAction RequiredActionProviderRepresentation) error {
	const errMessage = "could not create required action"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(requiredAction).
		Post(g.getAdminRealmURL(realm, "authentication", "register-required-action"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return err
	}

	return err
}

// GetRequiredActions gets a list of required actions for a given realm
func (g *GoKeycloak) GetRequiredActions(ctx context.Context, token string, realm string) ([]*RequiredActionProviderRepresentation, error) {
	const errMessage = "could not get required actions"
	var result []*RequiredActionProviderRepresentation

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "required-actions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, err
}

// GetRequiredAction gets a required action for a given realm
func (g *GoKeycloak) GetRequiredAction(ctx context.Context, token string, realm string, alias string) (*RequiredActionProviderRepresentation, error) {
	const errMessage = "could not get required action"
	var result RequiredActionProviderRepresentation

	if alias == "" {
		return nil, errors.New("alias is required for getting a required action")
	}

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "authentication", "required-actions", alias))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, err
}

// UpdateRequiredAction updates a required action for a given realm
func (g *GoKeycloak) UpdateRequiredAction(ctx context.Context, token string, realm string, requiredAction RequiredActionProviderRepresentation) error {
	const errMessage = "could not update required action"

	if NilOrEmpty(requiredAction.ProviderID) {
		return errors.New("providerId is required for updating a required action")
	}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(requiredAction).
		Put(g.getAdminRealmURL(realm, "authentication", "required-actions", *requiredAction.ProviderID))

	return checkForError(resp, err, errMessage)
}

// DeleteRequiredAction updates a required action for a given realm
func (g *GoKeycloak) DeleteRequiredAction(ctx context.Context, token string, realm string, alias string) error {
	const errMessage = "could not delete required action"

	if alias == "" {
		return errors.New("alias is required for deleting a required action")
	}
	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		Delete(g.getAdminRealmURL(realm, "authentication", "required-actions", alias))

	if err := checkForError(resp, err, errMessage); err != nil {
		return err
	}

	return err
}

// CreateClientScopesScopeMappingsClientRoles attaches a client role to a client scope (not client's scope)
func (g *GoKeycloak) CreateClientScopesScopeMappingsClientRoles(
	ctx context.Context, token, realm, idOfClientScope, idOfClient string, roles []Role,
) error {
	const errMessage = "could not create client-level roles to the client-scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(g.getAdminRealmURL(realm, "client-scopes", idOfClientScope, "scope-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// GetClientScopesScopeMappingsClientRolesAvailable returns available (i.e. not attached via
// CreateClientScopesScopeMappingsClientRoles) client roles for a specific client, for a client scope
// (not client's scope).
func (g *GoKeycloak) GetClientScopesScopeMappingsClientRolesAvailable(ctx context.Context, token, realm, idOfClientScope, idOfClient string) ([]*Role, error) {
	const errMessage = "could not get available client-level roles with the client-scope"

	var result []*Role

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "client-scopes", idOfClientScope, "scope-mappings", "clients", idOfClient, "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopesScopeMappingsClientRoles returns attached client roles for a specific client, for a client scope
// (not client's scope).
func (g *GoKeycloak) GetClientScopesScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClientScope, idOfClient string) ([]*Role, error) {
	const errMessage = "could not get client-level roles with the client-scope"

	var result []*Role

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.getAdminRealmURL(realm, "client-scopes", idOfClientScope, "scope-mappings", "clients", idOfClient))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteClientScopesScopeMappingsClientRoles removes attachment of client roles from a client scope
// (not client's scope).
func (g *GoKeycloak) DeleteClientScopesScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClientScope, idOfClient string, roles []Role) error {
	const errMessage = "could not delete client-level roles from the client-scope"

	resp, err := g.GetRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(g.getAdminRealmURL(realm, "client-scopes", idOfClientScope, "scope-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}



func (g *GoKeycloak) GenerateClientInitialAccessToken(ctx context.Context, realm string, adminAccessToken string, requestBody ClientInitialAccessTokenRequest) (ClientInitialAccessTokenResponse, error) {
	const errMessage = "could not generate client initial access token"

	var request ClientInitialAccessTokenRequest = requestBody	

	if request.Count < 1 {
		request.Count = 1
	}
	if request.Expiration < int(time.Minute.Seconds()) {
		request.Expiration = int(time.Minute.Seconds()* 5)
	}

	var result ClientInitialAccessTokenResponse

	resp, err := g.GetRequestWithBearerAuth(ctx, adminAccessToken).
		SetResult(&result).		
		SetBody(request).
		Post(g.getAdminRealmURL(realm, "clients-initial-access"))
	return result, checkForError(resp, err, errMessage)
}