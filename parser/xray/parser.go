package xray

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/parser/subscription"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

// ParseXraySubscription reads a subscription written as Xray configurations:
// either one document, or the array of complete documents - one per server -
// that panels commonly hand out.
func ParseXraySubscription(_ context.Context, content string) (subscription.Result, error) {
	documents, recognized := xrayDocuments(content)
	if !recognized {
		return subscription.Result{}, subscription.ErrUnrecognized
	}
	collector := subscription.NewCollector("Xray")
	for index, rawDocument := range documents {
		var config document
		if err := json.Unmarshal(rawDocument, &config); err != nil {
			collector.Skip("", F.ToString("Xray document ", index+1), err)
			continue
		}
		parseDocument(collector, config, index)
	}
	return collector.Result(), nil
}

// xrayDocuments reports whether the content is a set of Xray configurations, whose outbounds name
// a protocol rather than a type; read as sing-box or Clash the same array would be other servers.
func xrayDocuments(content string) ([]json.RawMessage, bool) {
	trimmed := strings.TrimSpace(content)
	var documents []json.RawMessage
	switch {
	case strings.HasPrefix(trimmed, "["):
		if json.Unmarshal([]byte(trimmed), &documents) != nil {
			return nil, false
		}
	case strings.HasPrefix(trimmed, "{"):
		documents = []json.RawMessage{json.RawMessage(trimmed)}
	default:
		return nil, false
	}
	for _, rawDocument := range documents {
		var probe struct {
			Outbounds []struct {
				Protocol string `json:"protocol"`
			} `json:"outbounds"`
		}
		if json.Unmarshal(rawDocument, &probe) != nil {
			continue
		}
		for _, outbound := range probe.Outbounds {
			if outbound.Protocol != "" {
				return documents, true
			}
		}
	}
	return nil, false
}

func parseDocument(collector *subscription.Collector, config document, documentIndex int) {
	var nodes []parsedOutbound
	directTags := make(map[string]bool)
	refusedTags := make(map[string]bool)
	for index, rawOutbound := range config.Outbounds {
		var source struct {
			Tag string `json:"tag"`
		}
		named := json.Unmarshal(rawOutbound, &source) == nil && source.Tag != ""
		label := F.ToString("Xray server ", documentIndex+1, ".", index+1)
		if named {
			label += " (" + source.Tag + ")"
		}
		node, err := parseSourceOutbound(rawOutbound, F.ToString("server-", documentIndex+1, "-", index+1))
		if err == nil {
			nodes = append(nodes, node)
			continue
		}
		if errors.Is(err, errNotAServer) {
			if named {
				if errors.Is(err, errDropsTraffic) {
					refusedTags[source.Tag] = true
				} else {
					directTags[source.Tag] = true
				}
			}
			continue
		}
		if named {
			refusedTags[source.Tag] = true
		}
		collector.Skip("", label, err)
	}
	if len(nodes) == 0 {
		return
	}
	// A document with remarks is one server of a subscription, named by the remarks. It may hold
	// several servers reached through routing rules a provider does not import; Xray dials the first
	// outbound when no rule matches, so that one is imported with what it dials through.
	if remarks := strings.TrimSpace(config.Remarks); remarks != "" {
		nodes = reachableFrom(nodes)
		nodes[0].outbound.Tag = remarks
	}
	tagMap := make(map[string]string, len(nodes))
	for index := range nodes {
		nodes[index].outbound.Tag = collector.UniqueTag(nodes[index].outbound.Tag)
		if _, taken := tagMap[nodes[index].sourceTag]; !taken {
			tagMap[nodes[index].sourceTag] = nodes[index].outbound.Tag
		}
	}
	for _, node := range nodes {
		detour := node.detour
		switch {
		case detour == "":
		case directTags[detour]:
			// Xray's freedom outbound is a plain connection, which sing-box
			// writes as no detour at all.
			detour = ""
		case tagMap[detour] != "":
			detour = tagMap[detour]
		case refusedTags[detour]:
			collector.Skip(node.outbound.Tag, F.ToString("Xray server ", node.outbound.Tag),
				E.New("dials through an outbound that could not be imported"))
			continue
		default:
			// A tag the document never defines names an outbound the rest of
			// the configuration provides, and is left alone.
		}
		if detour != node.detour {
			dialer := node.outbound.Options.(option.DialerOptionsWrapper)
			dialerOptions := dialer.TakeDialerOptions()
			dialerOptions.Detour = detour
			dialer.ReplaceDialerOptions(dialerOptions)
		}
		collector.Add(node.outbound)
	}
}

// reachableFrom keeps the document's first server and the ones it dials
// through, so a server described as a chain does not lose its base.
func reachableFrom(nodes []parsedOutbound) []parsedOutbound {
	byTag := make(map[string]parsedOutbound, len(nodes))
	for _, node := range nodes {
		if _, taken := byTag[node.sourceTag]; !taken {
			byTag[node.sourceTag] = node
		}
	}
	// The server the document dials comes first, so it is the one the remarks
	// name; the bases follow in the order the document wrote them.
	result := []parsedOutbound{nodes[0]}
	reached := map[string]bool{nodes[0].sourceTag: true}
	for detour := nodes[0].detour; detour != ""; {
		node, isInternal := byTag[detour]
		if !isInternal || reached[detour] {
			break
		}
		reached[detour] = true
		result = append(result, node)
		detour = node.detour
	}
	return result
}
