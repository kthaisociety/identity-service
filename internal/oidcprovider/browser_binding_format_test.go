package oidcprovider

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func mustBrowserBinding(t *testing.T) string {
	t.Helper()
	value, err := NewBrowserBinding()
	require.NoError(t, err)
	return value
}

func TestBrowserBindingAcceptsOnlyCanonicalGeneratedFormat(t *testing.T) {
	require.True(t, ValidBrowserBinding(mustBrowserBinding(t)))
	// A valid shape alone does not prove that the server issued the value.
	require.True(t, ValidBrowserBinding(strings.Repeat("A", 43)))
	for name, value := range map[string]string{
		"empty":               "",
		"short":               "banana",
		"long":                strings.Repeat("A", 44),
		"padded":              strings.Repeat("A", 43) + "=",
		"invalid character":   strings.Repeat("A", 42) + "!",
		"noncanonical ending": strings.Repeat("A", 42) + "B",
	} {
		t.Run(name, func(t *testing.T) {
			require.False(t, ValidBrowserBinding(value))
		})
	}
}

func TestMalformedBrowserBindingCannotReachStore(t *testing.T) {
	s := testStore(t)
	valid := mustBrowserBinding(t)
	ctx := WithBrowserBinding(context.Background(), valid)
	request, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{ClientID: "app"}, "")
	require.NoError(t, err)

	_, err = s.CreateAuthRequest(WithBrowserBinding(context.Background(), "banana"), &oidc.AuthRequest{ClientID: "app"}, "")
	require.Error(t, err)
	_, err = s.CreateAuthRequest(WithBrowserBinding(ctx, "banana"), &oidc.AuthRequest{ClientID: "app"}, "")
	require.Error(t, err, "an invalid value must replace any earlier context binding")
	_, err = s.AuthRequestForBrowser(context.Background(), request.GetID(), "banana")
	require.Error(t, err)
	_, err = s.AuthRequestForBrowser(context.Background(), request.GetID(), valid)
	require.NoError(t, err)
}
