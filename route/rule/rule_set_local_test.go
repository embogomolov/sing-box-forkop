package rule

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func TestDamagedLocalRuleSetFailsStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "damaged.list")
	if err := os.WriteFile(path, []byte("<html>denied</html>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewLocalRuleSet(context.Background(), logger.NOP(), "damaged", option.RuleSet{
		Type:   C.RuleSetTypeLocal,
		Tag:    []string{"damaged"},
		Format: C.RuleSetFormatAuto,
		LocalOptions: option.LocalRuleSet{
			Path: path,
		},
	})
	if err == nil {
		t.Fatal("damaged local rule-set was accepted")
	}
}

// The extension of a rule-set carries no promise about its content, so auto has
// to read the file by what is in it and report what it turned out to be.
func TestLocalAutoRuleSetIgnoresFileExtension(t *testing.T) {
	var binary bytes.Buffer
	err := srs.Write(&binary, option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{
			DomainSuffix: []string{"example.com"},
		},
	}}}, C.RuleSetVersionCurrent)
	if err != nil {
		t.Fatal(err)
	}
	for name, testCase := range map[string]struct {
		file    string
		content []byte
		format  string
	}{
		"binary-named-json":   {"rules.json", binary.Bytes(), C.RuleSetFormatBinary},
		"source-named-text":   {"rules.txt", []byte(`{"version":4,"rules":[{"domain_suffix":["example.com"]}]}`), C.RuleSetFormatSource},
		"text-named-binary":   {"rules.srs", []byte("example.com\n"), C.RuleSetFormatText},
		"text-without-name":   {"rules", []byte("example.com\n"), C.RuleSetFormatText},
		"binary-without-name": {"rules-binary", binary.Bytes(), C.RuleSetFormatBinary},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), testCase.file)
			if err := os.WriteFile(path, testCase.content, 0o600); err != nil {
				t.Fatal(err)
			}
			ruleSet, err := NewLocalRuleSet(context.Background(), logger.NOP(), "auto", option.RuleSet{
				Type:   C.RuleSetTypeLocal,
				Tag:    []string{"auto"},
				Format: C.RuleSetFormatAuto,
				LocalOptions: option.LocalRuleSet{
					Path: path,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer ruleSet.Close()
			if snapshot := ruleSet.ProviderSnapshot(); snapshot.Format != testCase.format {
				t.Fatalf("reported format %q instead of the detected %q", snapshot.Format, testCase.format)
			}
			metadata := testMetadata("www.example.com")
			if !ruleSet.Match(&metadata) {
				t.Fatal("detected rule-set did not match its own domain")
			}
		})
	}
}
