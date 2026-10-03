package engine

import (
	"context"
	"sync"
	"time"
)

// limiter 对单个目标限制并发请求数与请求速率（令牌间隔法）。
type limiter struct {
	sem      chan struct{}
	interval time.Duration // 两次请求的最小间隔，<=0 表示不限速

	mu   sync.Mutex
	next time.Time // 下一个允许发起请求的时刻
}

func newLimiter(concurrency int, ratePerSec float64) *limiter {
	if concurrency <= 0 {
		concurrency = 1
	}
	l := &limiter{sem: make(chan struct{}, concurrency)}
	if ratePerSec > 0 {
		l.interval = time.Duration(float64(time.Second) / ratePerSec)
	}
	return l
}

// acquire 获取一次请求许可，先占并发槽再等待速率窗口；ctx 取消时返回错误。
func (l *limiter) acquire(ctx context.Context) error {
	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if l.interval <= 0 {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	wait := time.Duration(0)
	if now.Before(l.next) {
		wait = l.next.Sub(now)
		l.next = l.next.Add(l.interval)
	} else {
		l.next = now.Add(l.interval)
	}
	l.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		l.release()
		return ctx.Err()
	}
}

func (l *limiter) release() {
	select {
	case <-l.sem:
	default:
	}
}
