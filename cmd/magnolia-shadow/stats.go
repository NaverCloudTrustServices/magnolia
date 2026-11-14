package main

import (
	"fmt"
	"html/template"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

type metrics struct {
	registry    *prometheus.Registry
	registerer  prometheus.Registerer    // adds the metrics prefix
	submissions *prometheus.CounterVec   // by result
	issuances   *prometheus.CounterVec   // by result, see [result]
	duration    prometheus.Histogram     // of successful issuances
	identifiers prometheus.Histogram     // per submitted certificate
	requests    *prometheus.HistogramVec // by endpoint and status

	// The summary served at / is computed from the fields below, which
	// duplicate what the collectors above count.
	mu    sync.Mutex
	start time.Time
	// seconds is a ring of the last hour, indexed by Unix time.
	seconds [3600]second
	// latencies is a ring of the most recent successful issuances.
	latencies [4096]time.Duration
	issued    int
	failed    int
	failures  map[string]int // by result
}

type second struct {
	unix           int64
	issued, failed int
}

func newMetrics() *metrics {
	m := &metrics{
		registry: prometheus.NewRegistry(),
		submissions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "addchain_requests_total",
			Help: "Number of add-chain requests, by result.",
		}, []string{"result"}),
		issuances: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "issuances_total",
			Help: "Number of submitted certificates, by the result of shadowing them: " +
				"issued, dropped, unparsable, timeout, transport, protocol, or the ACME error type.",
		}, []string{"result"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "issuance_duration_seconds",
			Help:    "Time from sending the newOrder request to the finalize response, for successful issuances.",
			Buckets: []float64{.05, .1, .25, .5, .75, 1, 1.5, 2, 3, 5, 10, 20, 30, 60},
		}),
		identifiers: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "identifiers",
			Help:    "Number of identifiers in each submitted certificate.",
			Buckets: []float64{1, 2, 3, 5, 10, 25, 50, 100},
		}),
		requests: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "acme_request_duration_seconds",
			Help:    "Duration of requests to the CA, by endpoint and HTTP status, or error if there was no response.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60},
		}, []string{"endpoint", "status"}),
		start:    time.Now(),
		failures: make(map[string]int),
	}
	m.registry.MustRegister(collectors.NewGoCollector())
	m.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m.registerer = prometheus.WrapRegistererWithPrefix("magnolia_shadow_", m.registry)
	m.registerer.MustRegister(
		m.submissions, m.issuances, m.duration, m.identifiers, m.requests)
	return m
}

// record counts a submitted certificate, with the outcome of shadowing it
// (see [result]) and how long the issuance took.
func (m *metrics) record(result string, elapsed time.Duration) {
	m.issuances.WithLabelValues(result).Inc()
	if result == "issued" {
		m.duration.Observe(elapsed.Seconds())
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().Unix()
	s := &m.seconds[now%int64(len(m.seconds))]
	if s.unix != now {
		*s = second{unix: now}
	}
	if result == "issued" {
		s.issued++
		m.latencies[m.issued%len(m.latencies)] = elapsed
		m.issued++
	} else {
		s.failed++
		m.failed++
		m.failures[result]++
	}
}

// summary is the data of the home page.
type summary struct {
	Directory string
	LogID     string
	PublicKey string

	Rate        string // issued per second in the last minute
	Windows     []windowSummary
	Chart       string // points of a polyline in a ChartWidth by 100 box
	ChartWidth  int
	ChartPeak   string
	Issued      string
	Failed      string
	InFlight    string
	MaxInFlight string
	Uptime      string

	Latencies    string // number of issuances the percentiles are of, if any
	P50, P90     string
	P99, Slowest string

	Failures []failureSummary
}

type windowSummary struct {
	Name           string
	Issued, Failed string
}

type failureSummary struct {
	Result string
	Count  string
}

const chartSeconds = 300

func (m *metrics) summary() *summary {
	p := message.NewPrinter(language.English)

	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()

	// Only seconds that are over are counted, so that rates don't dip.
	last := now.Unix() - 1
	count := func(window int64) (issued, failed int) {
		for t := last; t > last-window; t-- {
			if s := m.seconds[t%int64(len(m.seconds))]; s.unix == t {
				issued += s.issued
				failed += s.failed
			}
		}
		return issued, failed
	}
	rate := func(n int, window int64) string {
		window = max(1, min(window, last-m.start.Unix()+1))
		return p.Sprintf("%.1f", float64(n)/float64(window))
	}

	s := &summary{
		Issued: p.Sprintf("%d", m.issued),
		Failed: p.Sprintf("%d", m.failed),
		Uptime: now.Sub(m.start).Round(time.Second).String(),
	}
	for _, w := range []struct {
		name    string
		seconds int64
	}{{"last minute", 60}, {"last 5 minutes", 300}, {"last hour", 3600}} {
		issued, failed := count(w.seconds)
		s.Windows = append(s.Windows, windowSummary{
			Name: w.name, Issued: rate(issued, w.seconds), Failed: rate(failed, w.seconds),
		})
	}
	s.Rate = s.Windows[0].Issued

	var points []int
	for t := last - chartSeconds + 1; t <= last; t++ {
		n := 0
		if s := m.seconds[t%int64(len(m.seconds))]; s.unix == t {
			n = s.issued
		}
		points = append(points, n)
	}
	peak := slices.Max(points)
	var chart strings.Builder
	for i, n := range points {
		fmt.Fprintf(&chart, "%d,%.1f ", i, 100-100*float64(n)/float64(max(peak, 1)))
	}
	s.Chart = chart.String()
	s.ChartWidth = chartSeconds - 1
	s.ChartPeak = p.Sprintf("%d", peak)

	latencies := slices.Sorted(slices.Values(m.latencies[:min(m.issued, len(m.latencies))]))
	if n := len(latencies); n > 0 {
		ms := func(d time.Duration) string { return d.Round(time.Millisecond).String() }
		s.Latencies = p.Sprintf("%d", n)
		s.P50 = ms(latencies[n*50/100])
		s.P90 = ms(latencies[n*90/100])
		s.P99 = ms(latencies[n*99/100])
		s.Slowest = ms(latencies[n-1])
	}

	for _, result := range slices.Sorted(maps.Keys(m.failures)) {
		s.Failures = append(s.Failures, failureSummary{
			Result: result, Count: p.Sprintf("%d", m.failures[result]),
		})
	}
	slices.SortStableFunc(s.Failures, func(a, b failureSummary) int {
		return m.failures[b.Result] - m.failures[a.Result]
	})

	return s
}

func (sh *shadow) handleHome(w http.ResponseWriter, r *http.Request) {
	p := message.NewPrinter(language.English)
	s := sh.metrics.summary()
	s.Directory = sh.client.directoryURL
	s.LogID = sh.signer.LogID()
	s.PublicKey = sh.signer.PublicKey()
	s.InFlight = p.Sprintf("%d", len(sh.inflight))
	s.MaxInFlight = p.Sprintf("%d", cap(sh.inflight))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := homeTemplate.Execute(w, s); err != nil {
		sh.logger.Error("failed to render home page", "err", err)
	}
}

var homeTemplate = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>magnolia-shadow</title>
<style>
:root { color-scheme: light dark; }
body { font: 1rem/1.5 ui-monospace, monospace; max-width: 44rem; margin: 3rem auto; padding: 0 1rem; }
h1, h2 { font-size: 1rem; margin-top: 3rem; }
big { display: block; font-size: 6rem; font-weight: bold; line-height: 1; }
svg { display: block; width: 100%; height: 8rem; border-bottom: 1px solid; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: right; font-weight: normal; padding: 0; }
th:first-child, td:first-child { text-align: left; }
p { overflow-wrap: anywhere; }
</style>

<h1>magnolia-shadow</h1>

<p>This is not a Certificate Transparency log, and it logs nothing. Every
certificate submitted to its add-chain endpoint gets a throwaway SCT, and then
a Merkle Tree Certificate with the same names and a random ML-DSA-44 key is
requested from the ACME server at {{.Directory}}, as a load test.

<h2>Certificates issued per second, last minute</h2>

<big>{{.Rate}}</big>

<h2>Certificates issued each second, last 5 minutes, peak {{.ChartPeak}}</h2>

<svg viewBox="0 0 {{.ChartWidth}} 100" preserveAspectRatio="none" role="img" aria-label="Chart of certificates issued each second">
<polyline points="{{.Chart}}" fill="none" stroke="currentColor" stroke-width="1.5" vector-effect="non-scaling-stroke"/>
</svg>

<h2>Rates</h2>

<table>
<tr><th><th>issued/s<th>failed/s
{{range .Windows}}<tr><td>{{.Name}}<td>{{.Issued}}<td>{{.Failed}}
{{end}}</table>

<h2>Totals, up for {{.Uptime}}</h2>

<table>
<tr><td>issued<td>{{.Issued}}
<tr><td>failed<td>{{.Failed}}
<tr><td>in flight<td>{{.InFlight}} of at most {{.MaxInFlight}}
</table>

{{if .Latencies}}<h2>Time to issue, last {{.Latencies}} certificates</h2>

<table>
<tr><td>median<td>{{.P50}}
<tr><td>90th percentile<td>{{.P90}}
<tr><td>99th percentile<td>{{.P99}}
<tr><td>slowest<td>{{.Slowest}}
</table>

{{end}}{{if .Failures}}<h2>Failures</h2>

<table>
{{range .Failures}}<tr><td>{{.Result}}<td>{{.Count}}
{{end}}</table>

{{end}}<h2>Log</h2>

<p>Log ID: {{.LogID}}
<p>Public key: {{.PublicKey}}
<p><a href="/metrics">Metrics</a>
`))
