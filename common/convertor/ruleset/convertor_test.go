package ruleset

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestAutoDetectionRejectsDamagedInput(t *testing.T) {
	for name, content := range map[string]string{
		"json":    `{not-json`,
		"binary":  "SRS\x03\x00",
		"text":    "example.com\n<html>denied</html>\n",
		"yaml":    "payload:\n  - example.com\n",
		"hosts":   "0.0.0.0 ads.example.com\n",
		"adblock": "[Adblock Plus 2.0]\n||ads.example.com^\n",
		"status":  "Forbidden\n",
		"empty":   "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Read(strings.NewReader(content), C.RuleSetFormatAuto); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestAutoDetectsSupportedFormats(t *testing.T) {
	plainRuleSet := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{
			DomainSuffix: []string{"example.com"},
		},
	}}}
	var binary bytes.Buffer
	if err := srs.Write(&binary, plainRuleSet, C.RuleSetVersionCurrent); err != nil {
		t.Fatal(err)
	}
	for name, testCase := range map[string]struct {
		content []byte
		format  string
	}{
		"binary":         {binary.Bytes(), C.RuleSetFormatBinary},
		"source":         {[]byte("// comment\n{\"version\":4,\"rules\":[{\"domain_suffix\":[\"example.com\"]}]}"), C.RuleSetFormatSource},
		"source-hash":    {[]byte("# comment\n{\"version\":4,\"rules\":[{\"domain_suffix\":[\"example.com\"]}]}"), C.RuleSetFormatSource},
		"source-block":   {[]byte("/* comment */\n{\"version\":4,\"rules\":[{\"domain_suffix\":[\"example.com\"]}]}"), C.RuleSetFormatSource},
		"text":           {[]byte("example.com\n"), C.RuleSetFormatText},
		"text-commented": {[]byte("# a list\nexample.com\n"), C.RuleSetFormatText},
	} {
		t.Run(name, func(t *testing.T) {
			ruleSet, format, err := Read(bytes.NewReader(testCase.content), C.RuleSetFormatAuto)
			if err != nil {
				t.Fatal(err)
			}
			if format != testCase.format || len(ruleSet.Rules) == 0 {
				t.Fatalf("unexpected result: format=%q rules=%d", format, len(ruleSet.Rules))
			}
		})
	}
}

func TestReadSkipsByteOrderMark(t *testing.T) {
	content := "\ufeff{\"version\":4,\"rules\":[{\"domain_suffix\":[\"example.com\"]}]}"
	for _, requested := range []string{C.RuleSetFormatSource, C.RuleSetFormatAuto} {
		t.Run(requested, func(t *testing.T) {
			ruleSet, format, err := Read(strings.NewReader(content), requested)
			if err != nil {
				t.Fatal(err)
			}
			if format != C.RuleSetFormatSource || len(ruleSet.Rules) != 1 {
				t.Fatalf("unexpected result: format=%q rules=%d", format, len(ruleSet.Rules))
			}
		})
	}
}

func TestReadRejectsUnknownFormat(t *testing.T) {
	if _, _, err := Read(strings.NewReader("example.com\n"), "yaml"); err == nil {
		t.Fatal("expected an unknown format error")
	}
}
