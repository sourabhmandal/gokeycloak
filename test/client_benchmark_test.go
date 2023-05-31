package gokeycloak_test

import (
	"context"
	"testing"

	"github.com/sourabhmandal/gokeycloak"
	"github.com/stretchr/testify/assert"
)

func BenchmarkLogin(b *testing.B) {
	cfg := GetConfig(b)
	client := gokeycloak.NewClient(cfg.HostName)
	SetUpTestUser(b, client)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := client.Login(
			context.Background(),
			cfg.GoKeycloak.ClientID,
			cfg.GoKeycloak.ClientSecret,
			cfg.GoKeycloak.Realm,
			cfg.GoKeycloak.UserName,
			cfg.GoKeycloak.Password,
		)
		assert.NoError(b, err, "Failed %d", i)
	}
}

func BenchmarkLoginParallel(b *testing.B) {
	cfg := GetConfig(b)
	client := gokeycloak.NewClient(cfg.HostName)
	SetUpTestUser(b, client)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := client.Login(
				context.Background(),
				cfg.GoKeycloak.ClientID,
				cfg.GoKeycloak.ClientSecret,
				cfg.GoKeycloak.Realm,
				cfg.GoKeycloak.UserName,
				cfg.GoKeycloak.Password,
			)
			assert.NoError(b, err)
		}
	})
}

func BenchmarkGetGroups(b *testing.B) {
	cfg := GetConfig(b)
	client := gokeycloak.NewClient(cfg.HostName)
	token := GetAdminToken(b, client)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := client.GetGroups(
			context.Background(),
			token.AccessToken,
			cfg.GoKeycloak.Realm,
			gokeycloak.GetGroupsParams{},
		)
		assert.NoError(b, err)
	}
}

func BenchmarkGetGroupsFull(b *testing.B) {
	cfg := GetConfig(b)
	client := gokeycloak.NewClient(cfg.HostName)
	token := GetAdminToken(b, client)
	params := gokeycloak.GetGroupsParams{
		Full: gokeycloak.BoolP(true),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := client.GetGroups(
			context.Background(),
			token.AccessToken,
			cfg.GoKeycloak.Realm,
			params,
		)
		assert.NoError(b, err)
	}
}

func BenchmarkGetGroupsBrief(b *testing.B) {
	cfg := GetConfig(b)
	client := gokeycloak.NewClient(cfg.HostName)
	params := gokeycloak.GetGroupsParams{
		BriefRepresentation: gokeycloak.BoolP(true),
	}
	token := GetAdminToken(b, client)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := client.GetGroups(
			context.Background(),
			token.AccessToken,
			cfg.GoKeycloak.Realm,
			params,
		)
		assert.NoError(b, err)
	}
}

func BenchmarkGetGroup(b *testing.B) {
	cfg := GetConfig(b)
	client := gokeycloak.NewClient(cfg.HostName)
	teardown, groupID := CreateGroup(b, client)
	defer teardown()
	token := GetAdminToken(b, client)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := client.GetGroup(
			context.Background(),
			token.AccessToken,
			cfg.GoKeycloak.Realm,
			groupID,
		)
		assert.NoError(b, err)
	}
}

func BenchmarkGetGroupByPath(b *testing.B) {
	cfg := GetConfig(b)
	client := gokeycloak.NewClient(cfg.HostName)
	teardown, groupID := CreateGroup(b, client)
	token := GetAdminToken(b, client)
	_, group, err := client.GetGroup(context.Background(), token.AccessToken, cfg.GoKeycloak.Realm, groupID)
	assert.NoError(b, err)
	defer teardown()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := client.GetGroupByPath(
			context.Background(),
			token.AccessToken,
			cfg.GoKeycloak.Realm,
			*group.Path,
		)
		assert.NoError(b, err)
	}
}
