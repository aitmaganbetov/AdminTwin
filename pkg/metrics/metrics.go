// Package metrics — meta-monitoring платформы (M24, §17.4): счётчики и гистограммы в текстовом
// формате Prometheus без внешних зависимостей. Метки — только с ограниченной кардинальностью
// (шаблон маршрута, метод, статус); идентификаторы объектов в метки не попадают.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
)

// Registry — набор метрик.
type Registry struct {
	mu       sync.Mutex
	counters map[string]*series
	hists    map[string]*hist
	gauges   []func() []Gauge
	help     map[string]string
}

type series struct{ values map[string]float64 }

type hist struct {
	buckets []float64
	counts  map[string][]uint64
	sum     map[string]float64
	n       map[string]uint64
}

// Gauge — значение, вычисляемое при сборе.
type Gauge struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// New создаёт реестр.
func New() *Registry {
	return &Registry{counters: map[string]*series{}, hists: map[string]*hist{}, help: map[string]string{}}
}

// Help задаёт описание метрики.
func (r *Registry) Help(name, text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.help[name] = text
}

// Inc увеличивает счётчик.
func (r *Registry) Inc(name string, labels map[string]string, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.counters[name]
	if !ok {
		s = &series{values: map[string]float64{}}
		r.counters[name] = s
	}
	s.values[labelString(labels)] += v
}

// Observe добавляет наблюдение в гистограмму (секунды).
func (r *Registry) Observe(name string, labels map[string]string, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.hists[name]
	if !ok {
		h = &hist{buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.8, 1, 1.5, 2.5, 5, 10},
			counts: map[string][]uint64{}, sum: map[string]float64{}, n: map[string]uint64{}}
		r.hists[name] = h
	}
	k := labelString(labels)
	if h.counts[k] == nil {
		h.counts[k] = make([]uint64, len(h.buckets))
	}
	for i, b := range h.buckets {
		if v <= b {
			h.counts[k][i]++
		}
	}
	h.sum[k] += v
	h.n[k]++
}

// GaugeFunc регистрирует вычисляемые метрики.
func (r *Registry) GaugeFunc(f func() []Gauge) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges = append(r.gauges, f)
}

// Write выводит метрики в текстовом формате Prometheus.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	names := make([]string, 0, len(r.counters))
	for n := range r.counters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r.header(w, n, "counter")
		for _, k := range sortedKeys(r.counters[n].values) {
			fmt.Fprintf(w, "%s%s %s\n", n, k, num(r.counters[n].values[k]))
		}
	}
	hn := make([]string, 0, len(r.hists))
	for n := range r.hists {
		hn = append(hn, n)
	}
	sort.Strings(hn)
	for _, n := range hn {
		h := r.hists[n]
		r.header(w, n, "histogram")
		for _, k := range sortedKeys(h.n) {
			inner := strings.TrimSuffix(strings.TrimPrefix(k, "{"), "}")
			sep := ""
			if inner != "" {
				sep = ","
			}
			for i, b := range h.buckets {
				fmt.Fprintf(w, "%s_bucket{%s%sle=\"%s\"} %d\n", n, inner, sep, num(b), h.counts[k][i])
			}
			fmt.Fprintf(w, "%s_bucket{%s%sle=\"+Inf\"} %d\n", n, inner, sep, h.n[k])
			fmt.Fprintf(w, "%s_sum%s %s\n", n, k, num(h.sum[k]))
			fmt.Fprintf(w, "%s_count%s %d\n", n, k, h.n[k])
		}
	}
	gs := append([]func() []Gauge(nil), r.gauges...)
	help := r.help
	r.mu.Unlock()

	byName := map[string][]Gauge{}
	for _, f := range gs {
		for _, g := range f() {
			byName[g.Name] = append(byName[g.Name], g)
		}
	}
	gn := make([]string, 0, len(byName))
	for n := range byName {
		gn = append(gn, n)
	}
	sort.Strings(gn)
	for _, n := range gn {
		if h, ok := help[n]; ok {
			fmt.Fprintf(w, "# HELP %s %s\n", n, h)
		}
		fmt.Fprintf(w, "# TYPE %s gauge\n", n)
		for _, g := range byName[n] {
			fmt.Fprintf(w, "%s%s %s\n", n, labelString(g.Labels), num(g.Value))
		}
	}
}

func (r *Registry) header(w io.Writer, n, typ string) {
	if h, ok := r.help[n]; ok {
		fmt.Fprintf(w, "# HELP %s %s\n", n, h)
	}
	fmt.Fprintf(w, "# TYPE %s %s\n", n, typ)
}

func labelString(l map[string]string) string {
	if len(l) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(l[k])
		parts = append(parts, k+`="`+v+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func num(f float64) string {
	if math.IsInf(f, 1) {
		return "+Inf"
	}
	return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.6f", f), "0"), ".")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
