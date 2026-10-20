package cloudflare

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestGetProfileKeepsTheTokenItWasAskedWith(t *testing.T) {
	api := &CloudflareApi{client: http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer auth-token" {
			t.Errorf("unexpected authorization %q", request.Header.Get("Authorization"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"id":"profile-id","account":{"license":"old"}}`)),
			Header:     make(http.Header),
		}, nil
	})}}
	profile, err := api.GetProfile(context.Background(), "auth-token", "profile-id")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Token != "auth-token" {
		t.Fatalf("profile token %q, want the one it was read with", profile.Token)
	}
}
