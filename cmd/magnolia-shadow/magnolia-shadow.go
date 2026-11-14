// Command magnolia-shadow is an experiment that load tests an MTC CA by
// shadowing the issuance of another CA.
//
// It serves the RFC 6962 add-chain endpoint of a Certificate Transparency log
// that doesn't exist. For every submitted chain it returns an SCT, and then
// requests from the CA, over ACME, a certificate for a random ML-DSA-44 key
// with the identifiers of the submitted certificate.
//
// The SCTs are valid, and signed by a stable key, so that submitters that
// verify them don't fail. They are returned before issuance is attempted, so
// the CA being slow or failing is never visible to the submitter. Nothing is
// logged, so the SCTs must not be used.
//
// It listens for plain HTTP, and is meant to run behind a reverse proxy that
// terminates TLS. A summary is served at /, metrics are exposed at /metrics,
// and logs are written to stderr.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	fs := flag.NewFlagSet("magnolia-shadow", flag.ExitOnError)
	listenFlag := fs.String("listen", "localhost:8080", "address to listen on for plain HTTP")
	directoryFlag := fs.String("directory", "", "ACME directory URL of the CA")
	caAddrFlag := fs.String("ca-addr", "", "host:port to reach the CA at over cleartext HTTP/2, "+
		"instead of the host of the directory URL over HTTPS")
	keyFlag := fs.String("key", "magnolia-shadow.pem", "path to the SCT signing key, created if missing")
	inflightFlag := fs.Int("max-inflight", 1000, "number of concurrent issuances beyond which submissions are dropped")
	timeoutFlag := fs.Duration("timeout", time.Minute, "time limit of each issuance")
	fs.Parse(os.Args[1:])

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if *directoryFlag == "" {
		fatalError(logger, "missing -directory flag")
	}
	if *inflightFlag <= 0 {
		fatalError(logger, "-max-inflight must be positive")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	signer, created, err := loadSCTSigner(*keyFlag)
	if err != nil {
		fatalError(logger, "failed to load SCT signing key", "path", *keyFlag, "err", err)
	}
	logger.Info("loaded SCT signing key", "path", *keyFlag, "created", created,
		"logID", signer.LogID(), "publicKey", signer.PublicKey())

	m := newMetrics()
	client, err := newACMEClient(ctx, newHTTPClient(*caAddrFlag), *directoryFlag, m.requests)
	if err != nil {
		fatalError(logger, "failed to set up ACME account", "directory", *directoryFlag, "err", err)
	}
	logger.Info("created ACME account", "directory", *directoryFlag, "account", client.kid)

	sh := newShadow(logger, signer, client, m, *inflightFlag, *timeoutFlag)

	s := &http.Server{
		Handler:      sh.Handler(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		// Longer than the reverse proxy keeps idle connections for, so that
		// it's never this side that closes a connection a submission is being
		// sent on, which the proxy would turn into an error.
		IdleTimeout: 5 * time.Minute,
		ErrorLog: slog.NewLogLogger(logger.Handler().WithAttrs(
			[]slog.Attr{slog.String("source", "http")},
		), slog.LevelWarn),
	}
	l, err := net.Listen("tcp", *listenFlag)
	if err != nil {
		fatalError(logger, "failed to listen", "addr", *listenFlag, "err", err)
	}
	logger.Info("listening", "addr", l.Addr())
	go func() {
		if err := s.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			logger.Error("serve error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	// Issuances in flight get a few seconds to finish. The CA completes the
	// ones that are abandoned regardless.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		logger.Error("failed to shut down server", "err", err)
	}
	done := make(chan struct{})
	go func() { sh.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		logger.Error("abandoned issuances in flight", "inflight", len(sh.inflight))
	}

	os.Exit(1)
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}

// newHTTPClient returns the client used to reach the CA. If caAddr is not
// empty, every request is sent to it over cleartext HTTP/2, like a reverse
// proxy in front of the CA would, regardless of its URL.
func newHTTPClient(caAddr string) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 100
	if caAddr == "" {
		return &http.Client{Transport: t}
	}
	t.Protocols = new(http.Protocols)
	t.Protocols.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: &reroutedTransport{addr: caAddr, rt: t}}
}

type reroutedTransport struct {
	addr string
	rt   http.RoundTripper
}

func (t *reroutedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Host = req.URL.Host
	req.URL.Scheme = "http"
	req.URL.Host = t.addr
	return t.rt.RoundTrip(req)
}

// shadow turns add-chain submissions into issuances.
type shadow struct {
	logger  *slog.Logger
	signer  *sctSigner
	client  *acmeClient
	metrics *metrics
	timeout time.Duration
	// inflight holds a token for each issuance in progress.
	inflight chan struct{}
	wg       sync.WaitGroup
}

func newShadow(logger *slog.Logger, signer *sctSigner, client *acmeClient, m *metrics, maxInflight int, timeout time.Duration) *shadow {
	sh := &shadow{
		logger:   logger,
		signer:   signer,
		client:   client,
		metrics:  m,
		timeout:  timeout,
		inflight: make(chan struct{}, maxInflight),
	}
	m.registerer.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "inflight_issuances",
		Help: "Number of issuances in progress.",
	}, func() float64 { return float64(len(sh.inflight)) }))
	return sh
}

func (sh *shadow) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ct/v1/add-chain", sh.handleAddChain)
	mux.HandleFunc("GET /{$}", sh.handleHome)
	mux.Handle("GET /metrics", promhttp.HandlerFor(sh.metrics.registry, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(sh.logger.Handler().WithAttrs(
			[]slog.Attr{slog.String("source", "metrics")},
		), slog.LevelWarn),
	}))
	return mux
}

// Wait blocks until there are no issuances in flight.
func (sh *shadow) Wait() { sh.wg.Wait() }

// handleAddChain implements the add-chain endpoint of RFC 6962, Section 4.1.
// The chain is not verified, and any non-empty first entry gets an SCT, even
// if it is not a certificate that can be shadowed.
func (sh *shadow) handleAddChain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Chain [][]byte `json:"chain"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err == nil {
		err = json.Unmarshal(body, &req)
	}
	if err == nil && (len(req.Chain) == 0 || len(req.Chain[0]) == 0) {
		err = errors.New("chain is empty")
	}
	if err != nil {
		sh.metrics.submissions.WithLabelValues("rejected").Inc()
		sh.logger.Error("rejected add-chain request", "err", err)
		http.Error(w, "invalid add-chain request: "+err.Error(), http.StatusBadRequest)
		return
	}
	leaf := req.Chain[0]

	sct, err := sh.signer.Sign(leaf, time.Now())
	if err != nil {
		sh.metrics.submissions.WithLabelValues("error").Inc()
		sh.logger.Error("failed to sign SCT", "err", err)
		http.Error(w, "failed to sign SCT: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sh.metrics.submissions.WithLabelValues("accepted").Inc()

	sh.shadow(leaf)

	w.Header().Set("Content-Type", "application/json")
	json.MarshalWrite(w, sct)
}

// shadow starts the issuance of a certificate with the identifiers of leaf,
// without waiting for it, unless there are too many issuances in flight.
func (sh *shadow) shadow(leaf []byte) {
	select {
	case sh.inflight <- struct{}{}:
	default:
		sh.metrics.record("dropped", 0)
		sh.logger.Error("dropped submission, too many issuances in flight", "inflight", cap(sh.inflight))
		return
	}
	sh.wg.Go(func() {
		defer func() { <-sh.inflight }()
		ctx, cancel := context.WithTimeout(context.Background(), sh.timeout)
		defer cancel()

		cert, err := x509.ParseCertificate(leaf)
		if err != nil {
			sh.metrics.record("unparsable", 0)
			sh.logger.Error("failed to parse submitted certificate", "err", err)
			return
		}
		ids := identifiers(cert)
		sh.metrics.identifiers.Observe(float64(len(ids)))

		start := time.Now()
		_, err = sh.client.issue(ctx, ids, &x509.CertificateRequest{
			DNSNames:    cert.DNSNames,
			IPAddresses: cert.IPAddresses,
		})
		elapsed := time.Since(start)
		res := result(err)
		sh.metrics.record(res, elapsed)
		if err != nil {
			attrs := []any{"result", res, "err", err, "elapsed", elapsed,
				"serial", cert.SerialNumber.Text(16), "identifiers", ids}
			if p, ok := errors.AsType[*problem](err); ok {
				attrs = append(attrs, "problem", string(p.body))
			}
			sh.logger.Error("issuance failed", attrs...)
		}
	})
}

// identifiers returns the ACME identifiers for the DNS names and IP addresses
// of cert, as they are, leaving it to the CA to reject them.
func identifiers(cert *x509.Certificate) []identifier {
	ids := make([]identifier, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	for _, name := range cert.DNSNames {
		ids = append(ids, identifier{Type: "dns", Value: name})
	}
	for _, ip := range cert.IPAddresses {
		addr, _ := netip.AddrFromSlice(ip)
		ids = append(ids, identifier{Type: "ip", Value: addr.String()})
	}
	return ids
}

// result returns the label an issuance that ended with err is counted under:
// "issued", the short name of the ACME error type returned by the CA,
// "timeout", "transport" for requests that got no response, or "protocol" for
// responses that are not what an ACME client expects.
func result(err error) string {
	if err == nil {
		return "issued"
	}
	if p, ok := errors.AsType[*problem](err); ok {
		return p.Name()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if _, ok := errors.AsType[*url.Error](err); ok {
		return "transport"
	}
	return "protocol"
}
