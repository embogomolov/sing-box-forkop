package utils

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The versions are worked out when the package is initialized, and a router may start with its clock
// unset: they must stay those of real browsers, not go below zero and take every command down.
func TestBrowserVersionsWithClockUnset(t *testing.T) {
	for _, now := range []time.Time{time.Unix(0, 0), time.Date(2012, 3, 1, 0, 0, 0, 0, time.UTC)} {
		for i := 0; i < 100; i++ {
			chrome := ChromeVersion(now)
			require.GreaterOrEqual(t, chrome, 140, now)
			require.NotPanics(t, func() { getGreasedChUa(chrome, "chrome") }, now)
			require.GreaterOrEqual(t, FirefoxVersion(now), 126, now)
			minor, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(CurlVersion(now), "8."), ".0"))
			require.NoError(t, err, now)
			require.GreaterOrEqual(t, minor, 0, now)
			require.True(t, strings.HasPrefix(SafariVersion(now), "26."), now)
		}
	}
}
