package provider

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestPrepareSubscriptionContentMetadata(t *testing.T) {
	body := "upload=1; download=2; total=10; expire=20\nvless://uuid@example.com:443#node"
	headers := http.Header{
		"Profile-Title":            []string{"base64:SGVhZGVyIHRpdGxl"},
		"Subscription-Userinfo":    []string{"upload=7; total=100"},
		"Profile-Web-Page-Url":     []string{"https://example.com/account"},
		"Support-Url":              []string{"javascript:alert(1)"},
		"Announce":                 []string{"base64:TWFpbnRlbmFuY2UKc29vbg=="},
		"Announce-Url":             []string{"https://example.com/news"},
		"Subscription-Refill-Date": []string{"30"},
		"Content-Disposition":      []string{`attachment; filename="../nodes.txt"`},
	}

	content, info, metadata := prepareSubscriptionContent(body, metadataHeaderValues(headers))
	if content != "vless://uuid@example.com:443#node" {
		t.Fatalf("userinfo preamble was not removed: %q", content)
	}
	if info.Upload != 7 || info.Download != 0 || info.Total != 100 || info.Expire != 0 {
		t.Fatalf("header did not override the userinfo line: %+v", info)
	}
	if metadata.Title != "Header title" || metadata.WebPageURL != "https://example.com/account" {
		t.Fatalf("unexpected profile metadata: %+v", metadata)
	}
	if metadata.SupportURL != "" || metadata.Announce != "Maintenance soon" || metadata.AnnounceURL != "https://example.com/news" {
		t.Fatalf("metadata was not safely normalized: %+v", metadata)
	}
	if metadata.RefillDate != 30 || metadata.FileName != ".._nodes.txt" {
		t.Fatalf("unexpected refill or filename metadata: %+v", metadata)
	}
}

func TestProviderCacheMetadataRoundTrip(t *testing.T) {
	info := adapter.SubscriptionInfo{Upload: 1, Download: 2, Total: 3, Expire: 4}
	metadata := adapter.SubscriptionMetadata{Title: "Example", SupportURL: "https://example.com/support"}
	content := encodeProviderCacheMetadata(info, metadata) + "\n" + `{"outbounds":[]}`
	decodedContent, decodedInfo, decodedMetadata, loaded := decodeProviderCacheContent(content)
	if !loaded || decodedContent != `{"outbounds":[]}` || decodedInfo != info || decodedMetadata != metadata {
		t.Fatalf("cache metadata did not round-trip: content=%q info=%+v metadata=%+v", decodedContent, decodedInfo, decodedMetadata)
	}

	for name, cached := range map[string]string{
		"invalid metadata": providerCacheMetadataPrefix + "invalid\n" + `{"outbounds":[]}`,
		"missing metadata": "upload=9; total=10\n" + `{"outbounds":[]}`,
	} {
		if _, _, _, loaded = decodeProviderCacheContent(cached); loaded {
			t.Fatalf("a cache entry with %s was restored", name)
		}
	}
}

func TestProviderCacheIdentityIncludesTheRequest(t *testing.T) {
	base := providerCacheIdentity("https://example.com/sub", "sing-box", http.Header{"X-Token": {"one"}})
	for name, changed := range map[string][]byte{
		"url":        providerCacheIdentity("https://example.com/other", "sing-box", http.Header{"X-Token": {"one"}}),
		"user agent": providerCacheIdentity("https://example.com/sub", "other", http.Header{"X-Token": {"one"}}),
		"header":     providerCacheIdentity("https://example.com/sub", "sing-box", http.Header{"X-Token": {"two"}}),
	} {
		if bytes.Equal(changed, base) {
			t.Fatalf("%s did not affect provider cache identity", name)
		}
	}
}

func TestMergeSubscriptionHeadersPreservesUnspecifiedCacheMetadata(t *testing.T) {
	info := adapter.SubscriptionInfo{Upload: 1, Total: 10}
	metadata := adapter.SubscriptionMetadata{Title: "Old", SupportURL: "https://example.com/support"}
	info, metadata = mergeSubscriptionData(info, metadata, map[string]string{"profile-title": "New"})
	if info.Upload != 1 || info.Total != 10 || metadata.Title != "New" || metadata.SupportURL != "https://example.com/support" {
		t.Fatalf("partial 304 metadata replaced cached values: info=%+v metadata=%+v", info, metadata)
	}
}
