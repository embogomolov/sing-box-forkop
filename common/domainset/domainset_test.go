package domainset

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"

	"github.com/sagernet/sing/common/domain"

	"github.com/stretchr/testify/require"
)

// names makes count names of no pattern, some with a dot in front, some repeated, some not of
// ASCII.
func names(random *rand.Rand, count int) []string {
	letters := "abcdefghijklmnopqrstuvwxyz0123456789-"
	tlds := []string{"com", "net", "org", "ru", "io", "co.uk", "рф", "xn--p1ai"}
	result := make([]string, 0, count)
	for len(result) < count {
		var name strings.Builder
		if random.Intn(10) == 0 {
			name.WriteByte('.')
		}
		for range 1 + random.Intn(3) {
			for range 1 + random.Intn(10) {
				name.WriteByte(letters[random.Intn(26)])
			}
			if random.Intn(5) == 0 {
				name.WriteString("-" + string(letters[random.Intn(len(letters))]))
			}
			name.WriteByte('.')
		}
		name.WriteString(tlds[random.Intn(len(tlds))])
		result = append(result, name.String())
		if random.Intn(20) == 0 && len(result) < count {
			result = append(result, result[random.Intn(len(result))])
		}
	}
	return result
}

func singBytes(t *testing.T, domains []string, domainSuffix []string) []byte {
	var content bytes.Buffer
	require.NoError(t, domain.NewMatcher(domains, domainSuffix, false).Write(&content))
	return content.Bytes()
}

// The matcher is sing's byte for byte: names and suffixes of no pattern, repeated, in both
// lists, with a dot in front, not of ASCII, from one to many.
func TestSameAsSing(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	for _, count := range []int{1, 2, 3, 10, 100, 1000, 20000} {
		domains, suffixes := names(random, count), names(random, count)
		domains = append(domains, suffixes[0])
		suffixes = append(suffixes, "."+strings.TrimPrefix(domains[0], "."))
		for _, lists := range [][2][]string{{domains, suffixes}, {domains, nil}, {nil, suffixes}} {
			want := singBytes(t, lists[0], lists[1])
			require.Equal(t, want, encode(lists[0], lists[1]), "%d names", count)
			matcher, err := NewMatcher(lists[0], lists[1])
			require.NoError(t, err)
			var written bytes.Buffer
			require.NoError(t, matcher.Write(&written))
			require.Equal(t, want, written.Bytes())
			for _, name := range append(lists[0], lists[1]...) {
				name = strings.TrimPrefix(name, ".")
				for _, query := range []string{name, "sub." + name, "x" + name} {
					require.Equal(t, domain.NewMatcher(lists[0], lists[1], false).Match(query), matcher.Match(query), query)
				}
				break
			}
		}
	}
	for _, lists := range [][2][]string{
		{{"example.com"}, nil}, {nil, {"example.com"}}, {nil, {".example.com"}},
		{{"a.b.c", "b.c"}, {"c", ".b.c"}}, {{"x"}, {"x"}}, {{"\nx"}, {"x"}},
	} {
		require.Equal(t, singBytes(t, lists[0], lists[1]), encode(lists[0], lists[1]), "%q", lists)
	}
}

// What a list of 100000 names of no pattern costs to build: here and in sing.
func BenchmarkBuild(b *testing.B) {
	list := names(rand.New(rand.NewSource(2)), 100000)
	b.Run("domainset", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := NewMatcher(nil, list); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("sing", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			domain.NewMatcher(nil, list, false)
		}
	})
}
