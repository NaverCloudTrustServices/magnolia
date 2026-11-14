package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/ca"
	"geomys.org/magnolia/internal/lockstep"
	"geomys.org/magnolia/internal/namelists"
)

const (
	testCAID           = "66252.99999.1"
	testIssuanceOrigin = "oid/1.3.6.1.4.1.66252.99999.1.0.1"
	testEvidenceOrigin = "magnolia.test/evidence"
	testWritePrefix    = "https://magnolia.test/acme"
)

// newTestCA starts a CA serving cleartext HTTP/2, like magnolia-ca does behind
// a reverse proxy. It returns the address of the CA, and the directory where
// it stores certificates.
func newTestCA(t *testing.T) (addr, dir string) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelWarn}))
	newSigner := func(name string) *torchwood.CosignatureSigner {
		key, err := mldsa.GenerateKey(mldsa.MLDSA44())
		if err != nil {
			t.Fatal(err)
		}
		s, err := torchwood.NewCosignatureSigner(name, key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	dir = t.TempDir()
	backend, err := lockstep.NewLocalBackend(t.Context(), dir, logger)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(t.TempDir(), "lock.db")
	if err := lockstep.CreateSQLiteLockDatabase(lock); err != nil {
		t.Fatal(err)
	}
	caCosigner := newSigner("oid/1.3.6.1.4.1." + testCAID)
	evidenceSigner := newSigner(testEvidenceOrigin)
	signer, err := lockstep.NewSQLiteSigner(t.Context(), lock, logger,
		testIssuanceOrigin, []*torchwood.CosignatureSigner{caCosigner},
		testEvidenceOrigin, []*torchwood.CosignatureSigner{evidenceSigner})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })
	config := ca.IssuerConfig{
		CAID:       testCAID,
		ReadPrefix: "https://read.magnolia.test/" + testCAID,
		Logs: lockstep.Config{
			Logger:            logger,
			Backend:           backend,
			Signer:            signer,
			IssuanceOrigin:    testIssuanceOrigin,
			IssuanceVerifiers: []*torchwood.CosignatureVerifier{caCosigner.Verifier()},
			EvidenceOrigin:    testEvidenceOrigin,
			EvidenceVerifiers: []*torchwood.CosignatureVerifier{evidenceSigner.Verifier()},
		},
		SequencingPeriod: 10 * time.Millisecond,
	}
	if err := ca.CreateIssuer(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	iss, err := ca.LoadIssuer(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- iss.RunSequencer(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("sequencer: %v", err)
		}
	})

	tlds, err := namelists.ParseTLDs([]byte("COM\nEXAMPLE\n"))
	if err != nil {
		t.Fatal(err)
	}
	suffixes, err := namelists.ParsePublicSuffixes([]byte("// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n"))
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := namelists.ParseReservedIPs(
		[]byte("Address Block,Name\n10.0.0.0/8,Private-Use\n"),
		[]byte("Address Block,Name\n::1/128,Loopback Address\n"))
	if err != nil {
		t.Fatal(err)
	}
	accounts := filepath.Join(t.TempDir(), "accounts.db")
	if err := ca.CreateAccounts(accounts); err != nil {
		t.Fatal(err)
	}
	c, err := ca.New(ca.Config{
		WritePrefix: testWritePrefix,
		NonceKey:    bytes.Repeat([]byte{42}, 32),
		Accounts:    accounts,
		Issuer:      iss,
		Names:       namelists.Static(tlds, suffixes, reserved),
		NoNameLimit: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	// Nonces minted in the same millisecond the CA started are rejected.
	time.Sleep(2 * time.Millisecond)

	srv := httptest.NewUnstartedServer(c.Handler())
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), dir
}

// syncBuffer is a bytes.Buffer that can be read while it is written to.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newTestShadow returns a shadow with a new account on the CA at caAddr,
// along with its logs.
func newTestShadow(t *testing.T, caAddr string, maxInflight int) (*shadow, *syncBuffer) {
	t.Helper()
	signer, created, err := loadSCTSigner(filepath.Join(t.TempDir(), "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("the key was not reported as created")
	}
	m := newMetrics()
	client, err := newACMEClient(t.Context(), newHTTPClient(caAddr), testWritePrefix+"/directory", m.requests)
	if err != nil {
		t.Fatal(err)
	}
	logs := new(syncBuffer)
	logger := slog.New(slog.NewTextHandler(io.MultiWriter(logs, t.Output()), nil))
	sh := newShadow(logger, signer, client, m, maxInflight, 10*time.Second)
	t.Cleanup(sh.Wait)
	return sh, logs
}

// testLeaf returns a self-signed certificate with the given names.
func testLeaf(t *testing.T, dnsNames []string, ips []net.IP) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0xc0ffee),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// addChain submits a chain and checks that the response is a valid SCT for
// its first entry.
func addChain(t *testing.T, sh *shadow, chain ...[]byte) {
	t.Helper()
	body, err := json.Marshal(map[string][][]byte{"chain": chain})
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UnixMilli()
	rec := httptest.NewRecorder()
	sh.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/ct/v1/add-chain", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("add-chain: status %d, body %q", rec.Code, rec.Body)
	}
	var sct struct {
		SCTVersion *int   `json:"sct_version"`
		ID         []byte `json:"id"`
		Timestamp  int64  `json:"timestamp"`
		Extensions string `json:"extensions"`
		Signature  []byte `json:"signature"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sct, json.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("add-chain: %v in %q", err, rec.Body)
	}
	if sct.SCTVersion == nil || *sct.SCTVersion != 0 {
		t.Errorf("sct_version is not 0 in %q", rec.Body)
	}
	if sct.Extensions != "" {
		t.Errorf("extensions = %q, want none", sct.Extensions)
	}
	if now := time.Now().UnixMilli(); sct.Timestamp < before || sct.Timestamp > now {
		t.Errorf("timestamp = %d, want between %d and %d", sct.Timestamp, before, now)
	}
	spki, err := x509.MarshalPKIXPublicKey(&sh.signer.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if id := sha256.Sum256(spki); !bytes.Equal(sct.ID, id[:]) {
		t.Errorf("id = %x, want %x", sct.ID, id)
	}

	// RFC 6962, Section 3.2: version, signature type, timestamp, entry type,
	// certificate, and extensions.
	input := []byte{0, 0}
	input = binary.BigEndian.AppendUint64(input, uint64(sct.Timestamp))
	input = append(input, 0, 0)
	input = append(input, byte(len(chain[0])>>16), byte(len(chain[0])>>8), byte(len(chain[0])))
	input = append(input, chain[0]...)
	input = append(input, 0, 0)
	digest := sha256.Sum256(input)
	// SHA-256, ECDSA, and a 16-bit length.
	sig := sct.Signature
	if len(sig) < 4 || sig[0] != 4 || sig[1] != 3 || int(sig[2])<<8|int(sig[3]) != len(sig)-4 {
		t.Fatalf("signature %x is not a SHA-256 ECDSA DigitallySigned", sig)
	}
	if !ecdsa.VerifyASN1(&sh.signer.key.PublicKey, digest[:], sig[4:]) {
		t.Error("SCT signature doesn't verify")
	}
}

func TestIssued(t *testing.T) {
	caAddr, dir := newTestCA(t)
	sh, logs := newTestShadow(t, caAddr, 10)

	leaf := testLeaf(t, []string{"shadow.example.com", "*.wildcard.example.com"}, []net.IP{net.IPv4(8, 8, 4, 4)})
	addChain(t, sh, leaf, []byte("the chain is not looked at"))
	sh.Wait()

	if sh.metrics.issued != 1 || sh.metrics.failed != 0 {
		t.Fatalf("issued %d and failed %d, want 1 and 0", sh.metrics.issued, sh.metrics.failed)
	}
	if logs.String() != "" {
		t.Errorf("unexpected logs:\n%s", logs)
	}
	files, err := filepath.Glob(filepath.Join(dir, "certs", "*", "tbs", "*"))
	if err != nil || len(files) != 1 {
		t.Fatalf("certificates issued by the CA: %q, %v", files, err)
	}
	tbs, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"shadow.example.com", "*.wildcard.example.com", string([]byte{8, 8, 4, 4})} {
		if !bytes.Contains(tbs, []byte(name)) {
			t.Errorf("issued certificate doesn't include %q", name)
		}
	}
	rec := httptest.NewRecorder()
	sh.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<tr><td>issued<td>1\n") {
		t.Errorf("home page: status %d, body:\n%s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	sh.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{
		`magnolia_shadow_issuances_total{result="issued"} 1`,
		`magnolia_shadow_issuance_duration_seconds_count 1`,
		`magnolia_shadow_acme_request_duration_seconds_count{endpoint="finalize",status="200"} 1`,
		`magnolia_shadow_identifiers_sum 3`,
		`magnolia_shadow_inflight_issuances 0`,
	} {
		if !strings.Contains(rec.Body.String(), want+"\n") {
			t.Errorf("metrics don't include %q", want)
		}
	}
}

func TestFailures(t *testing.T) {
	caAddr, dir := newTestCA(t)

	t.Run("rejected by the CA", func(t *testing.T) {
		sh, logs := newTestShadow(t, caAddr, 10)
		addChain(t, sh, testLeaf(t, []string{"shadow.example.com", "shadow.invalid"}, nil))
		sh.Wait()
		if n := sh.metrics.failures["rejectedIdentifier"]; n != 1 || sh.metrics.issued != 0 {
			t.Errorf("failures = %v and issued = %d, want one rejectedIdentifier", sh.metrics.failures, sh.metrics.issued)
		}
		for _, want := range []string{"level=ERROR", "issuance failed", "result=rejectedIdentifier", "newOrder",
			"does not end in a public top-level domain", "serial=c0ffee", "shadow.invalid"} {
			if !strings.Contains(logs.String(), want) {
				t.Errorf("logs don't include %q:\n%s", want, logs)
			}
		}
	})

	t.Run("not a certificate", func(t *testing.T) {
		sh, logs := newTestShadow(t, caAddr, 10)
		addChain(t, sh, []byte("not a certificate"))
		sh.Wait()
		if n := sh.metrics.failures["unparsable"]; n != 1 || sh.metrics.issued != 0 {
			t.Errorf("failures = %v and issued = %d, want one unparsable", sh.metrics.failures, sh.metrics.issued)
		}
		if !strings.Contains(logs.String(), "level=ERROR") {
			t.Errorf("failure was not logged:\n%s", logs)
		}
	})

	t.Run("too many in flight", func(t *testing.T) {
		sh, logs := newTestShadow(t, caAddr, 1)
		sh.inflight <- struct{}{}
		addChain(t, sh, testLeaf(t, []string{"shadow.example.com"}, nil))
		<-sh.inflight
		sh.Wait()
		if n := sh.metrics.failures["dropped"]; n != 1 || sh.metrics.issued != 0 {
			t.Errorf("failures = %v and issued = %d, want one dropped", sh.metrics.failures, sh.metrics.issued)
		}
		if !strings.Contains(logs.String(), "level=ERROR") {
			t.Errorf("failure was not logged:\n%s", logs)
		}
	})

	t.Run("CA unreachable", func(t *testing.T) {
		sh, logs := newTestShadow(t, caAddr, 10)
		l, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			t.Fatal(err)
		}
		l.Close()
		sh.client.hc = newHTTPClient(l.Addr().String())
		addChain(t, sh, testLeaf(t, []string{"shadow.example.com"}, nil))
		sh.Wait()
		if n := sh.metrics.failures["transport"]; n != 1 || sh.metrics.issued != 0 {
			t.Errorf("failures = %v and issued = %d, want one transport", sh.metrics.failures, sh.metrics.issued)
		}
		if !strings.Contains(logs.String(), "level=ERROR") {
			t.Errorf("failure was not logged:\n%s", logs)
		}
	})

	if files, _ := filepath.Glob(filepath.Join(dir, "certs", "*", "tbs", "*")); len(files) != 0 {
		t.Errorf("the CA issued certificates: %q", files)
	}
}

func TestAddChainRejected(t *testing.T) {
	caAddr, _ := newTestCA(t)
	sh, _ := newTestShadow(t, caAddr, 10)
	for _, body := range []string{``, `{}`, `{"chain":[]}`, `{"chain":[""]}`, `{"chain":["not base64"]}`, `{"chain":"AAAA"}`} {
		rec := httptest.NewRecorder()
		sh.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/ct/v1/add-chain", strings.NewReader(body)))
		if rec.Code != 400 {
			t.Errorf("add-chain with body %q: status %d, want 400", body, rec.Code)
		}
	}
	sh.Wait()
	if sh.metrics.issued != 0 || sh.metrics.failed != 0 {
		t.Errorf("issued %d and failed %d, want none", sh.metrics.issued, sh.metrics.failed)
	}
}

func TestSCTSignerReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	first, created, err := loadSCTSigner(path)
	if err != nil || !created {
		t.Fatalf("first load: created = %v, err = %v", created, err)
	}
	second, created, err := loadSCTSigner(path)
	if err != nil || created {
		t.Fatalf("second load: created = %v, err = %v", created, err)
	}
	if first.LogID() != second.LogID() || !first.key.Equal(second.key) {
		t.Error("the key changed across loads")
	}
}
