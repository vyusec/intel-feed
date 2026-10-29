package service

import (
	"context"
	"testing"
	"time"
	"zoli.dev/intel-feed/internal/config"
)

func TestSlowBootstrapDoesNotBlockOtherSourceRefreshes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	trigger := make(chan struct{}, 1)
	slowStarted := make(chan struct{})
	fastRuns := make(chan struct{}, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sourceLoops(ctx, []config.Source{{Name: "slow"}, {Name: "fast"}}, time.Hour, trigger, func(source config.Source, _ bool) {
			if source.Name == "slow" {
				select {
				case <-slowStarted:
				default:
					close(slowStarted)
				}
				<-ctx.Done()
				return
			}
			fastRuns <- struct{}{}
		})
	}()
	wait := func(ch <-chan struct{}) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatal("independent source was blocked")
		}
	}
	wait(slowStarted)
	wait(fastRuns)
	trigger <- struct{}{}
	wait(fastRuns)
	cancel()
	wait(done)
}
