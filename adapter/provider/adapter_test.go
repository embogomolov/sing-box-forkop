package provider

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestFlagToCountryCodeAllFlags(t *testing.T) {
	for first := 'A'; first <= 'Z'; first++ {
		for second := 'A'; second <= 'Z'; second++ {
			flag := string(rune(0x1F1E6+(first-'A'))) + string(rune(0x1F1E6+(second-'A')))
			expected := string(first) + string(second)
			result := flagToCountryCode(flag)
			// flagToCountryCode appends a space
			if result != expected+" " {
				t.Errorf("flagToCountryCode(%q) = %q, want %q", expected, result, expected+" ")
			}
		}
	}
}

func TestRemoveEmojisFromTags(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"🇺🇸 United States", "US United States"},
		{"🇷🇺 Россия", "RU Россия"},
		{"🇩🇪 Germany 🚀", "DE Germany"},
		{"🇫🇷🇬🇧 France-UK", "FR GB France-UK"},
		{"No emojis here", "No emojis here"},
		{"🌍 World", "World"},
		{"🇯🇵 Tokyo ⚡ Fast", "JP Tokyo Fast"},
		{"Germany 🇩🇪", "Germany DE"},
		{"Server 🇺🇸 Node", "Server US Node"},
	}
	for _, tt := range tests {
		opts := []option.Outbound{{Tag: tt.input}}
		removeEmojisFromTags(opts)
		if opts[0].Tag != tt.expected {
			t.Errorf("removeEmojisFromTags(%q) = %q, want %q", tt.input, opts[0].Tag, tt.expected)
		}
	}
}
