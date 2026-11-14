package main

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
)

// acmeClient is an ACME client with a single ML-DSA-44 account, for a CA that
// validates challenges as soon as they are responded to.
type acmeClient struct {
	hc           *http.Client
	requests     *prometheus.HistogramVec // by endpoint and status
	directoryURL string
	key          *mldsa.PrivateKey
	kid          string
	dir          struct {
		NewNonce   string `json:"newNonce"`
		NewAccount string `json:"newAccount"`
		NewOrder   string `json:"newOrder"`
	}
	// nonces are the unspent nonces from previous responses.
	nonces chan string
}

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (id identifier) String() string { return id.Value }

// problem is an error response from the CA.
type problem struct {
	status int
	typ    string // empty if the response was not a problem document
	detail string
	body   []byte
}

func (p *problem) Error() string {
	if p.typ == "" {
		return fmt.Sprintf("HTTP %d: %q", p.status, p.body)
	}
	return fmt.Sprintf("HTTP %d %s: %s", p.status, p.typ, p.detail)
}

// Name returns the last component of the problem type, such as "malformed"
// for "urn:ietf:params:acme:error:malformed".
func (p *problem) Name() string {
	if p.typ == "" {
		return "http" + strconv.Itoa(p.status)
	}
	return p.typ[strings.LastIndexAny(p.typ, ":/")+1:]
}

// newACMEClient fetches the directory and creates an account with a new key.
func newACMEClient(ctx context.Context, hc *http.Client, directoryURL string, requests *prometheus.HistogramVec) (*acmeClient, error) {
	c := &acmeClient{
		hc:           hc,
		requests:     requests,
		directoryURL: directoryURL,
		nonces:       make(chan string, 4096),
	}
	resp, err := c.do(ctx, "directory", http.MethodGet, directoryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	if err := json.Unmarshal(resp.body, &c.dir); err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	if c.dir.NewNonce == "" || c.dir.NewAccount == "" || c.dir.NewOrder == "" {
		return nil, fmt.Errorf("directory: missing fields in %q", resp.body)
	}
	c.key, err = mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return nil, err
	}
	resp, err = c.post(ctx, "newAccount", c.dir.NewAccount, []byte(`{"termsOfServiceAgreed":true}`))
	if err != nil {
		return nil, fmt.Errorf("newAccount: %w", err)
	}
	c.kid = resp.header.Get("Location")
	if c.kid == "" {
		return nil, errors.New("newAccount: response has no Location")
	}
	return c, nil
}

// issue obtains a certificate for the identifiers, which must match those of
// the CSR template, with a new ML-DSA-44 key. It returns once the certificate
// is issued, with its URL, without downloading it.
func (c *acmeClient) issue(ctx context.Context, ids []identifier, template *x509.CertificateRequest) (string, error) {
	var order struct {
		Status         string   `json:"status"`
		Authorizations []string `json:"authorizations"`
		Finalize       string   `json:"finalize"`
		Certificate    string   `json:"certificate"`
	}
	payload, err := json.Marshal(map[string]any{"identifiers": ids})
	if err != nil {
		return "", err
	}
	resp, err := c.post(ctx, "newOrder", c.dir.NewOrder, payload)
	if err != nil {
		return "", fmt.Errorf("newOrder: %w", err)
	}
	if err := json.Unmarshal(resp.body, &order); err != nil {
		return "", fmt.Errorf("newOrder: %w", err)
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(8)
	for _, u := range order.Authorizations {
		g.Go(func() error { return c.authorize(gctx, u) })
	}
	if err := g.Wait(); err != nil {
		return "", err
	}

	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return "", err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return "", fmt.Errorf("creating CSR: %w", err)
	}
	payload, err = json.Marshal(map[string]string{"csr": base64.RawURLEncoding.EncodeToString(csr)})
	if err != nil {
		return "", err
	}
	// The CA responds to finalize requests once the certificate is issued.
	resp, err = c.post(ctx, "finalize", order.Finalize, payload)
	if err != nil {
		return "", fmt.Errorf("finalize: %w", err)
	}
	if err := json.Unmarshal(resp.body, &order); err != nil {
		return "", fmt.Errorf("finalize: %w", err)
	}
	if order.Status != "valid" {
		return "", fmt.Errorf("finalize: order is %q, not valid", order.Status)
	}
	return order.Certificate, nil
}

// authorize responds to the first challenge of an authorization, and expects
// it to be valid right away.
func (c *acmeClient) authorize(ctx context.Context, url string) error {
	var authz struct {
		Status     string `json:"status"`
		Challenges []struct {
			URL string `json:"url"`
		} `json:"challenges"`
	}
	resp, err := c.post(ctx, "authz", url, nil)
	if err != nil {
		return fmt.Errorf("authz: %w", err)
	}
	if err := json.Unmarshal(resp.body, &authz); err != nil {
		return fmt.Errorf("authz: %w", err)
	}
	if authz.Status == "valid" {
		return nil
	}
	if len(authz.Challenges) == 0 {
		return fmt.Errorf("authz: %q authorization has no challenges", authz.Status)
	}
	var challenge struct {
		Status string `json:"status"`
	}
	resp, err = c.post(ctx, "challenge", authz.Challenges[0].URL, []byte("{}"))
	if err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	if err := json.Unmarshal(resp.body, &challenge); err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	if challenge.Status != "valid" {
		return fmt.Errorf("challenge: challenge is %q, not valid", challenge.Status)
	}
	return nil
}

type response struct {
	header http.Header
	body   []byte
}

// post sends a request signed by the account key, or a POST-as-GET request
// if payload is empty, and returns its successful response. The endpoint is
// the label the request is counted under.
func (c *acmeClient) post(ctx context.Context, endpoint, url string, payload []byte) (*response, error) {
	var nonce string
	select {
	case nonce = <-c.nonces:
	default:
		resp, err := c.do(ctx, "newNonce", http.MethodHead, c.dir.NewNonce, nil)
		if err != nil {
			return nil, fmt.Errorf("newNonce: %w", err)
		}
		nonce = resp.header.Get("Replay-Nonce")
	}
	body, err := c.sign(url, nonce, payload)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, endpoint, http.MethodPost, url, body)
	// Nonces left unspent for too long, or across a restart of the CA, are
	// rejected, along with a fresh one to retry with.
	if p, ok := errors.AsType[*problem](err); ok && p.Name() == "badNonce" && resp.header.Get("Replay-Nonce") != "" {
		body, err = c.sign(url, resp.header.Get("Replay-Nonce"), payload)
		if err != nil {
			return nil, err
		}
		resp, err = c.do(ctx, endpoint, http.MethodPost, url, body)
	}
	if resp != nil {
		if nonce := resp.header.Get("Replay-Nonce"); nonce != "" {
			select {
			case c.nonces <- nonce:
			default:
			}
		}
	}
	return resp, err
}

// sign returns a JWS in the Flattened JSON Serialization, identifying the
// account key by its URL, or by value if the account doesn't exist yet.
func (c *acmeClient) sign(url, nonce string, payload []byte) ([]byte, error) {
	alg := c.key.PublicKey().Parameters().String()
	header := map[string]any{"alg": alg, "nonce": nonce, "url": url}
	if c.kid != "" {
		header["kid"] = c.kid
	} else {
		header["jwk"] = map[string]string{
			"kty": "AKP",
			"alg": alg,
			"pub": base64.RawURLEncoding.EncodeToString(c.key.PublicKey().Bytes()),
		}
	}
	h, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	protected := base64.RawURLEncoding.EncodeToString(h)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	sig, err := c.key.Sign(rand.Reader, []byte(protected+"."+encodedPayload), nil)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{
		"protected": protected,
		"payload":   encodedPayload,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})
}

// do sends a request and reads its response. If the status is not 2xx, it
// returns both the response and a [*problem].
func (c *acmeClient) do(ctx context.Context, endpoint, method, url string, body []byte) (*response, error) {
	start := time.Now()
	status := "error"
	defer func() {
		c.requests.WithLabelValues(endpoint, status).Observe(time.Since(start).Seconds())
	}()

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "geomys.org/magnolia/cmd/magnolia-shadow")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/jose+json")
	}
	hr, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer hr.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(hr.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	status = strconv.Itoa(hr.StatusCode)
	resp := &response{header: hr.Header, body: respBody}
	if hr.StatusCode/100 != 2 {
		p := &problem{status: hr.StatusCode, body: respBody}
		var doc struct {
			Type   string `json:"type"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(respBody, &doc) == nil {
			p.typ, p.detail = doc.Type, doc.Detail
		}
		return resp, p
	}
	return resp, nil
}
