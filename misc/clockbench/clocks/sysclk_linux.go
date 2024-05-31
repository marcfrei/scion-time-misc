//go:build linux

package clocks

// Based on Ntimed by Poul-Henning Kamp, https://github.com/bsdphk/Ntimed

import (
	"context"
	"log/slog"
	"math"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"example.com/clockbench/unixutil"
)

type adjustment struct {
	clock     *SystemClock
	duration  time.Duration
	afterFreq float64
}

type SystemClock struct {
	Log        *slog.Logger
	mu         sync.Mutex
	epoch      uint64
	adjustment *adjustment
}

func logfatal(ctx context.Context, log *slog.Logger, msg string, attrs ...slog.Attr) {
	// See https://pkg.go.dev/log/slog#hdr-Wrapping_output_methods
	var pcs [1]uintptr
	n := runtime.Callers(3, pcs[:]) // skip [Callers, logFatal, Fatal/FatalContext]
	if n != 1 {
		panic("unexpected call stack")
	}
	r := slog.NewRecord(time.Now(), slog.LevelError, msg, pcs[0])
	r.AddAttrs(attrs...)
	_ = log.Handler().Handle(ctx, r)
	os.Exit(1)
}

func fatal(log *slog.Logger, msg string, attrs ...slog.Attr) {
	logfatal(context.Background(), log, msg, attrs...)
}

func now(log *slog.Logger) time.Time {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_REALTIME, &ts)
	if err != nil {
		fatal(log, "unix.ClockGettime failed", slog.Any("error", err))
	}
	return time.Unix(ts.Unix()).UTC()
}

func sleep(log *slog.Logger, duration time.Duration) {
	fd, err := unix.TimerfdCreate(unix.CLOCK_REALTIME, unix.TFD_NONBLOCK)
	if err != nil {
		fatal(log, "unix.TimerfdCreate failed", slog.Any("error", err))
	}
	ts, err := unix.TimeToTimespec(now(log).Add(duration))
	if err != nil {
		fatal(log, "unix.TimeToTimespec failed", slog.Any("error", err))
	}
	err = unix.TimerfdSettime(fd, unix.TFD_TIMER_ABSTIME, &unix.ItimerSpec{Value: ts}, nil /* oldValue */)
	if err != nil {
		fatal(log, "unix.TimerfdSettime failed", slog.Any("error", err))
	}
	if fd < math.MinInt32 || math.MaxInt32 < fd {
		fatal(log, "unix.TimerfdCreate returned unexpected value")
	}
	pollFds := []unix.PollFd{
		{Fd: int32(fd), Events: unix.POLLIN},
	}
	for {
		_, err := unix.Poll(pollFds, -1 /* timeout */)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			fatal(log, "unix.Poll failed", slog.Any("error", err))
		}
		break
	}
	_ = unix.Close(fd)
}

func setOffset(log *slog.Logger, offset time.Duration) {
	log.LogAttrs(context.Background(), slog.LevelDebug,
		"setting time", slog.Duration("offset", offset))
	tx := unix.Timex{
		Modes: unix.ADJ_SETOFFSET | unix.ADJ_NANO,
		Time:  unixutil.NsecToNsecTimeval(offset.Nanoseconds()),
	}
	_, err := unix.ClockAdjtime(unix.CLOCK_REALTIME, &tx)
	if err != nil {
		fatal(log, "unix.ClockAdjtime failed", slog.Any("error", err))
	}
}

func setFrequency(log *slog.Logger, frequency float64) {
	log.LogAttrs(context.Background(), slog.LevelDebug,
		"setting frequency", slog.Float64("frequency", frequency))
	tx := unix.Timex{
		Modes:  unix.ADJ_FREQUENCY,
		Freq:   unixutil.FreqToScaledPPM(frequency),
	}
	_, err := unix.ClockAdjtime(unix.CLOCK_REALTIME, &tx)
	if err != nil {
		fatal(log, "unix.ClockAdjtime failed", slog.Any("error", err))
	}
}

func (c *SystemClock) Epoch() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch
}

func (c *SystemClock) Now() time.Time {
	return now(c.Log)
}

func (c *SystemClock) MaxDrift(duration time.Duration) time.Duration {
	return math.MaxInt64
}

func (c *SystemClock) Frequency() float64 {
	tx := unix.Timex{}
	_, err := unix.ClockAdjtime(unix.CLOCK_REALTIME, &tx)
	if err != nil {
		fatal(c.Log, "unix.ClockAdjtime failed", slog.Any("error", err))
	}
	return unixutil.FreqFromScaledPPM(tx.Freq)
}

func (c *SystemClock) Step(offset time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.adjustment != nil {
		setFrequency(c.Log, c.adjustment.afterFreq)
		c.adjustment = nil
	}
	setOffset(c.Log, offset)
	if c.epoch == math.MaxUint64 {
		panic("epoch overflow")
	}
	c.epoch++
}

func (c *SystemClock) AdjustFrequency(frequency float64) {
	setFrequency(c.Log, frequency)
}

func (c *SystemClock) AdjustOffset(offset, duration time.Duration, frequency float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.adjustment != nil {
		c.adjustment = nil
	}
	if duration < 0 {
		panic("invalid duration value")
	}
	duration = duration / time.Second * time.Second
	if duration == 0 {
		duration = time.Second
	}
	setFrequency(c.Log, frequency+offset.Seconds()/duration.Seconds())
	c.adjustment = &adjustment{
		clock:     c,
		duration:  duration,
		afterFreq: frequency,
	}
	go func(log *slog.Logger, adj *adjustment) {
		sleep(log, adj.duration)
		adj.clock.mu.Lock()
		defer adj.clock.mu.Unlock()
		if adj == adj.clock.adjustment {
			setFrequency(log, adj.afterFreq)
		}
	}(c.Log, c.adjustment)
}



func (c *SystemClock) Sleep(duration time.Duration) {
	c.Log.LogAttrs(context.Background(), slog.LevelDebug,
		"sleeping", slog.Duration("duration", duration))
	if duration < 0 {
		panic("invalid duration value")
	}
	sleep(c.Log, duration)
}
