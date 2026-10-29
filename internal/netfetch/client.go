// SPDX-License-Identifier: Apache-2.0
package netfetch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	HTTP  *http.Client
	Hosts map[string]bool
	Token string
}

func New(hosts []string, token string) *Client {
	allowed := map[string]bool{}
	for _, h := range hosts {
		allowed[h] = true
	}
	dial := &net.Dialer{Timeout: 15 * time.Second}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 30 * time.Second, MaxConnsPerHost: 4, IdleConnTimeout: 30 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if !allowed[host] || port != "443" {
				return nil, errors.New("destination not allowlisted")
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !publicIP(ip.IP) {
					return nil, errors.New("destination resolves to non-public address")
				}
			}
			for _, ip := range ips {
				c, err := dial.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
				if err == nil {
					return c, nil
				}
			}
			return nil, errors.New("connection failed")
		},
	}
	c := &Client{Hosts: allowed, Token: token}
	c.HTTP = &http.Client{Transport: transport, Timeout: 3 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("too many redirects")
		}
		return c.CheckURL(req.URL.String())
	}}
	return c
}
func publicIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !net.ParseIP("100.64.0.0").Equal(ip) && !inCIDR(ip, "100.64.0.0/10") && !inCIDR(ip, "192.0.0.0/24") && !inCIDR(ip, "198.18.0.0/15")
}
func inCIDR(ip net.IP, s string) bool { _, n, _ := net.ParseCIDR(s); return n.Contains(ip) }
func (c *Client) CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" || !c.Hosts[u.Hostname()] {
		return errors.New("URL is not an allowlisted HTTPS destination")
	}
	return nil
}

type Response struct {
	Body   []byte
	Header http.Header
	Status int
}

func (c *Client) Get(ctx context.Context, raw string, max int64, etag string) (Response, error) {
	var out Response
	if err := c.CheckURL(raw); err != nil {
		return out, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("User-Agent", "zoli-intel-feed/1.0")
		req.Header.Set("Accept", "application/json")
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		if req.URL.Hostname() == "api.github.com" {
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
			if c.Token != "" {
				req.Header.Set("Authorization", "Bearer "+c.Token)
			}
		}
		res, err := c.HTTP.Do(req)
		if err != nil {
			return out, err
		}
		out.Header = res.Header.Clone()
		out.Status = res.StatusCode
		if res.StatusCode == http.StatusNotModified {
			res.Body.Close()
			return out, nil
		}
		if req.URL.Hostname() == "api.github.com" && res.StatusCode == http.StatusForbidden && res.Header.Get("X-RateLimit-Remaining") == "0" {
			res.Body.Close()
			reset := "the next scheduled cycle"
			if stamp, err := strconv.ParseInt(res.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
				reset = time.Unix(stamp, 0).UTC().Format(time.RFC3339)
			}
			return out, fmt.Errorf("upstream api.github.com HTTP 403: API rate limit exhausted; configure a GitHub API token or retry after %s", reset)
		}
		if res.StatusCode == 429 || res.StatusCode >= 500 {
			res.Body.Close()
			wait := time.Duration(attempt+1) * time.Second
			if n, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil {
				wait = time.Duration(n) * time.Second
			}
			if wait > 30*time.Second || attempt == 2 {
				return out, fmt.Errorf("upstream %s HTTP %d; retry on next cycle", req.URL.Host, res.StatusCode)
			}
			select {
			case <-ctx.Done():
				return out, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		if res.StatusCode != 200 {
			res.Body.Close()
			return out, fmt.Errorf("upstream %s HTTP %d", req.URL.Host, res.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, max+1))
		res.Body.Close()
		if err != nil {
			return out, err
		}
		if int64(len(b)) > max {
			return out, errors.New("upstream response exceeds limit")
		}
		out.Body = b
		return out, nil
	}
	return out, errors.New("upstream retries exhausted")
}
func Hosts(urls ...string) []string {
	out := []string{}
	for _, s := range urls {
		u, err := url.Parse(s)
		if err == nil {
			out = append(out, strings.ToLower(u.Hostname()))
		}
	}
	return out
}
