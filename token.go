package gocloak

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
	"github.com/sourabhmandal/gokeycloak/v1/pkg/jwx"
)

// GetIssuer gets the issuer of the given realm
func (g *GoCloak) GetIssuer(ctx context.Context, realm string) (*IssuerResponse, error) {
	const errMessage = "could not get issuer"

	var result IssuerResponse
	resp, err := g.GetRequest(ctx).
		SetResult(&result).
		Get(g.getRealmURL(realm))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

func (g *GoCloak) decodeAccessTokenWithClaims(ctx context.Context, accessToken, realm string, claims jwt.Claims) (*jwt.Token, error) {
	const errMessage = "could not decode access token"
	accessToken = strings.Replace(accessToken, "Bearer ", "", 1)

	decodedHeader, err := jwx.DecodeAccessTokenHeader(accessToken)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	certResult, err := g.GetCerts(ctx, realm)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}
	if certResult.Keys == nil {
		return nil, errors.Wrap(errors.New("there is no keys to decode the token"), errMessage)
	}
	usedKey := findUsedKey(decodedHeader.Kid, *certResult.Keys)
	if usedKey == nil {
		return nil, errors.Wrap(errors.New("cannot find a key to decode the token"), errMessage)
	}

	if strings.HasPrefix(decodedHeader.Alg, "ES") {
		return jwx.DecodeAccessTokenECDSACustomClaims(accessToken, usedKey.X, usedKey.Y, usedKey.Crv, claims)
	} else if strings.HasPrefix(decodedHeader.Alg, "RS") {
		return jwx.DecodeAccessTokenRSACustomClaims(accessToken, usedKey.E, usedKey.N, claims)
	}
	return nil, fmt.Errorf("unsupported algorithm")
}

// DecodeAccessToken decodes the accessToken
func (g *GoCloak) DecodeAccessToken(ctx context.Context, accessToken, realm string) (*jwt.Token, *jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	token, err := g.decodeAccessTokenWithClaims(ctx, accessToken, realm, claims)
	if err != nil {
		return nil, nil, err
	}
	return token, &claims, nil
}

// DecodeAccessTokenCustomClaims decodes the accessToken and writes claims into the given claims
func (g *GoCloak) DecodeAccessTokenCustomClaims(ctx context.Context, accessToken, realm string, claims jwt.Claims) (*jwt.Token, error) {
	return g.decodeAccessTokenWithClaims(ctx, accessToken, realm, claims)
}
