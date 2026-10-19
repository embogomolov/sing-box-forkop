package openconnect

import (
	"testing"

	"github.com/sagernet/sing-openconnect"
)

func TestAuthChallengeWaitMessage(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name      string
		challenge openconnect.AuthChallenge
		expected  string
	}{
		{
			name: "refused password",
			challenge: openconnect.AuthChallenge{
				Error:   "Login failed.\n",
				Message: "Please enter your\nusername and password.",
				Form: &openconnect.AuthForm{Fields: []openconnect.AuthFormField{
					{Name: "username", Label: "Username:"},
					{Name: "password", Label: "Password:"},
				}},
			},
			expected: "waiting for authentication of Username, Password: Login failed.: Please enter your username and password.",
		},
		{
			name: "field without a label",
			challenge: openconnect.AuthChallenge{
				Form: &openconnect.AuthForm{Fields: []openconnect.AuthFormField{{Name: "group_list"}}},
			},
			expected: "waiting for authentication of group_list",
		},
		{
			name:      "browser",
			challenge: openconnect.AuthChallenge{Browser: &openconnect.BrowserRequest{URL: "https://sso.example.com"}},
			expected:  "waiting for browser authentication",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			message := authChallengeWaitMessage(&testCase.challenge)
			if message != testCase.expected {
				t.Fatalf("unexpected message %q", message)
			}
		})
	}
}
