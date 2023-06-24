package gokeycloak

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"github.com/zblocks/gokeycloak/pkg/jwx"
)

// GetIssuer gets the issuer of the given realm
func (g *GoKeycloak) GetIssuer(ctx context.Context, realm string) (int, *IssuerResponse, error) {
	const errMessage = "could not get issuer"

	var result IssuerResponse
	resp, err := g.GetRequest(ctx).
		SetResult(&result).
		Get(g.getRealmURL(realm))

	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &result, nil
}

func (g *GoKeycloak) decodeAccessTokenWithClaims(ctx context.Context, accessToken, realm string, claims jwt.Claims) (int, *jwt.Token, error) {
	const errMessage = "could not decode access token"
	accessToken = strings.Replace(accessToken, "Bearer ", "", 1)

	decodedHeader, err := jwx.DecodeAccessTokenHeader(accessToken)
	if err != nil {
		return http.StatusBadRequest, nil, errors.Wrap(err, errMessage)
	}

	statusCode, certResult, err := g.GetCerts(ctx, realm)
	if err != nil {
		return statusCode, nil, errors.Wrap(err, errMessage)
	}
	if certResult.Keys == nil {
		return statusCode, nil, errors.Wrap(errors.New("there is no keys to decode the token"), errMessage)
	}
	usedKey := findUsedKey(decodedHeader.Kid, *certResult.Keys)
	if usedKey == nil {
		return statusCode, nil, errors.Wrap(errors.New("cannot find a key to decode the token"), errMessage)
	}

	if strings.HasPrefix(decodedHeader.Alg, "ES") {
		token, err := jwx.DecodeAccessTokenECDSACustomClaims(accessToken, usedKey.X, usedKey.Y, usedKey.Crv, claims)
		return statusCode, token, err
	} else if strings.HasPrefix(decodedHeader.Alg, "RS") {
		token, err := jwx.DecodeAccessTokenRSACustomClaims(accessToken, usedKey.E, usedKey.N, claims)
		return statusCode, token, err
	}
	return statusCode, nil, fmt.Errorf("unsupported algorithm")
}

// DecodeAccessToken decodes the accessToken
func (g *GoKeycloak) DecodeAccessToken(ctx context.Context, accessToken, realm string) (int, *jwt.Token, *jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	statusCode, token, err := g.decodeAccessTokenWithClaims(ctx, accessToken, realm, claims)
	if err != nil {
		return statusCode, nil, nil, err
	}
	return statusCode, token, &claims, nil
}

// DecodeAccessTokenCustomClaims decodes the accessToken and writes claims into the given claims
func (g *GoKeycloak) DecodeAccessTokenCustomClaims(ctx context.Context, accessToken, realm string, claims jwt.Claims) (int, *jwt.Token, error) {
	return g.decodeAccessTokenWithClaims(ctx, accessToken, realm, claims)
}

// URL: {{keycloak_url}}/realms/{{realm}}/protocol/openid-connect/token
// GetRequestingPartyToken returns a requesting party token with permissions granted by the server
func (g *GoKeycloak) GetRequestingPartyToken(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (int, *JWT, error) {
	const errMessage = "could not get requesting party token"

	var res JWT

	resp, err := g.getRequestingParty(ctx, token, realm, options, &res)
	if err := checkForError(resp, err, errMessage); err != nil {
		return resp.StatusCode(), nil, err
	}

	return resp.StatusCode(), &res, nil
}