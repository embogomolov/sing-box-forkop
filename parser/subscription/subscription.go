// Package subscription holds what every subscription parser shares.
//
// A field that is not modelled but does not change how the connection is made is ignored; a field
// that decides where or how it is made and has no sing-box equivalent skips that one server with a
// reason. Either way the rest of the subscription is imported.
package subscription

import (
	"strconv"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

// ErrUnrecognized reports content not written in the parser's format, as opposed to entries of its
// format that are broken.
var ErrUnrecognized = E.New("unrecognized format")

// Skipped names one server the subscription described and the parser could not
// represent. Label identifies the entry the way the subscription did - by name
// or position - and never repeats its address or credentials.
type Skipped struct {
	Label  string
	Reason error
}

// Result is what a subscription turned out to describe: the servers that can be
// dialled, the ones that were left out, and the names of the entries that were
// refused, which anything dialling through them depends on.
type Result struct {
	// Format names the subscription format the content turned out to be in.
	Format    string
	Outbounds []option.Outbound
	Skipped   []Skipped
	Refused   map[string]bool
}

// Collector gathers one subscription's servers and keeps track of the entries
// that were refused, so a chain whose base is missing is not imported broken.
type Collector struct {
	format    string
	outbounds []option.Outbound
	skipped   []Skipped
	refused   map[string]bool
	direct    map[string]bool
	taken     map[string]bool
}

func NewCollector(format string) *Collector {
	return &Collector{
		format:  format,
		refused: make(map[string]bool),
		direct:  make(map[string]bool),
		taken:   make(map[string]bool),
	}
}

// Add keeps a server the parser could represent.
func (c *Collector) Add(outbound option.Outbound) {
	c.outbounds = append(c.outbounds, outbound)
}

// Skip leaves out one entry and records why. When the entry carried a tag,
// anything dialling through it is left out as well: a chain without its base
// would silently dial somewhere else.
func (c *Collector) Skip(tag string, label string, reason error) {
	if tag != "" {
		c.refused[tag] = true
	}
	c.skipped = append(c.skipped, Skipped{Label: label, Reason: reason})
}

// Direct marks an entry that is not a server but a plain connection - Xray's
// freedom outbound, Clash's DIRECT. Dialling through it is dialling directly,
// which sing-box writes as no detour at all.
func (c *Collector) Direct(tag string) {
	if tag != "" {
		c.direct[tag] = true
	}
}

// Discard marks an entry that throws away what it is handed - Clash's REJECT,
// Xray's blackhole. It is not a failure, but nothing can usefully dial through
// it, so its dependents are left out.
func (c *Collector) Discard(tag string) {
	if tag != "" {
		c.refused[tag] = true
	}
}

// Label composes the name of an entry for a report: its position, plus the name
// the subscription gave it when there is one.
func (c *Collector) Label(index int, name string) string {
	if name == "" {
		return F.ToString(c.format, " server ", index+1)
	}
	return F.ToString(c.format, " server ", index+1, " (", name, ")")
}

// Result reports what the subscription turned out to describe. Detours through
// an entry that stands for a plain connection are dropped here; the chains left
// dangling by a refused entry are resolved by the caller, which is the one
// place that knows how outbounds reference each other.
func (c *Collector) Result() Result {
	for _, outbound := range c.outbounds {
		dialer, isDialer := outbound.Options.(option.DialerOptionsWrapper)
		if !isDialer {
			continue
		}
		dialerOptions := dialer.TakeDialerOptions()
		if !c.direct[dialerOptions.Detour] {
			continue
		}
		dialerOptions.Detour = ""
		dialer.ReplaceDialerOptions(dialerOptions)
	}
	return Result{Format: c.format, Outbounds: c.outbounds, Skipped: c.skipped, Refused: c.refused}
}

// UniqueTag makes a name unique among the servers of this subscription, so a
// provider that tags every server the same way still produces distinguishable
// names instead of overwriting one with the next.
func (c *Collector) UniqueTag(base string) string {
	if base == "" {
		base = "server"
	}
	if !c.taken[base] {
		c.taken[base] = true
		return base
	}
	for suffix := 1; ; suffix++ {
		candidate := base + "-" + strconv.Itoa(suffix)
		if !c.taken[candidate] {
			c.taken[candidate] = true
			return candidate
		}
	}
}

// ReportSkipped logs one line per server the subscription described and the parser could not
// represent.
func ReportSkipped(logger log.ContextLogger, tag string, result Result) {
	if logger == nil {
		return
	}
	for _, skipped := range result.Skipped {
		logger.Warn("provider ", tag, ": skipped ", skipped.Label, ": ", skipped.Reason)
	}
}
