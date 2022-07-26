package httputil

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type metric struct {
	start, duration int64
}

type Timing struct {
	metrics map[string]metric
}

func NewTiming() *Timing {
	return &Timing{metrics: map[string]metric{}}
}

func (t *Timing) Start(name string) {
	var m = t.metrics[name]
	m.start = time.Now().UnixMicro()
	t.metrics[name] = m
}

func (t *Timing) Stop(name string) {
	var m = t.metrics[name]
	m.duration += time.Now().UnixMicro() - m.start
	t.metrics[name] = m
}

func (t Timing) Report(w http.ResponseWriter) {
	var values = make([]string, 0, len(t.metrics))
	for name, metric := range t.metrics {
		values = append(values, fmt.Sprintf("%s;dur=%.01f", name, float64(metric.duration)/1000))
	}
	w.Header().Set("Server-Timing", strings.Join(values, ","))
}
