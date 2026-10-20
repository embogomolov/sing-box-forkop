package rule

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type RuleSetUpdater struct {
	ctx      context.Context
	cancel   context.CancelFunc
	ruleSets []*RemoteRuleSet
}

func NewRuleSetUpdater(ctx context.Context, ruleSets []adapter.RuleSet) *RuleSetUpdater {
	var remoteRuleSets []*RemoteRuleSet
	for _, ruleSet := range ruleSets {
		remoteRuleSet, isRemote := ruleSet.(*RemoteRuleSet)
		if isRemote && remoteRuleSet.updateInterval > 0 {
			remoteRuleSets = append(remoteRuleSets, remoteRuleSet)
		}
	}
	if len(remoteRuleSets) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	return &RuleSetUpdater{
		ctx:      ctx,
		cancel:   cancel,
		ruleSets: remoteRuleSets,
	}
}

func (u *RuleSetUpdater) Start() {
	go u.loopUpdate()
}

func (u *RuleSetUpdater) Close() error {
	u.cancel()
	return nil
}

// ruleSetUpdateConcurrency is as many downloads at once as the start runs (route.Router).
const ruleSetUpdateConcurrency = 5

// A rule-set that started empty is retried after these delays, then every last one.
var ruleSetRetryDelays = []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second}

func (u *RuleSetUpdater) loopUpdate() {
	nextUpdates := make([]time.Time, len(u.ruleSets))
	retries := make([]int, len(u.ruleSets))
	for i, ruleSet := range u.ruleSets {
		nextUpdates[i] = ruleSet.updatedAt().Add(ruleSet.updateInterval)
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-timer.C:
		}
		now := time.Now()
		var due []int
		for i := range u.ruleSets {
			if !now.Before(nextUpdates[i]) {
				due = append(due, i)
			}
		}
		loaded := u.updateAll(due)
		if u.ctx.Err() != nil {
			return
		}
		var anyLoaded bool
		for _, i := range due {
			ruleSet := u.ruleSets[i]
			anyLoaded = anyLoaded || loaded[i]
			nextUpdates[i] = now.Add(ruleSet.updateInterval)
			if ruleSet.startedEmpty && ruleSet.updatedAt().IsZero() {
				nextUpdates[i] = now.Add(ruleSetRetryDelays[min(retries[i], len(ruleSetRetryDelays)-1)])
				retries[i]++
			}
		}
		// only a new list leaves the old one as garbage
		if anyLoaded {
			runtime.GC()
		}
		timer.Reset(waitUntilNext(nextUpdates))
	}
}

// updateAll reports by index which of the rule-sets loaded a new list.
func (u *RuleSetUpdater) updateAll(indexes []int) []bool {
	loaded := make([]bool, len(u.ruleSets))
	slots := make(chan struct{}, ruleSetUpdateConcurrency)
	var group sync.WaitGroup
	for _, i := range indexes {
		group.Add(1)
		slots <- struct{}{}
		go func(i int) {
			defer group.Done()
			defer func() { <-slots }()
			loaded[i] = u.ruleSets[i].updateOnce()
		}(i)
	}
	group.Wait()
	return loaded
}

func waitUntilNext(nextUpdates []time.Time) time.Duration {
	next := nextUpdates[0]
	for _, nextUpdate := range nextUpdates[1:] {
		if nextUpdate.Before(next) {
			next = nextUpdate
		}
	}
	wait := time.Until(next)
	if wait < 0 {
		return 0
	}
	return wait
}
