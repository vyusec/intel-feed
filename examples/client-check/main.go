// SPDX-License-Identifier: Apache-2.0
// client-check verifies a deployed feed and compares its cache with hosted lookup.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"zoli.dev/intel-feed/internal/netfetch"
	"zoli.dev/intel-feed/pkg/client"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	feedURL := flag.String("feed-url", "", "trusted HTTPS feed base URL ending in /feed")
	publicKey := flag.String("public-key", "", "pinned base64 Ed25519 public key")
	cachePath := flag.String("cache", "", "verified cache path (created on the first run)")
	queryJSON := flag.String("query", "", "one package identity as JSON")
	expectedStatus := flag.String("expect-status", "", "optional expected query status")
	flag.Parse()
	if flag.NArg() != 0 || *cachePath == "" || !strings.HasSuffix(strings.TrimRight(*feedURL, "/"), "/feed") {
		return errors.New("provide --feed-url ending in /feed, --public-key, --cache and --query; see -help")
	}
	if *expectedStatus != "" && *expectedStatus != "known_match" && *expectedStatus != "no_known_match" && *expectedStatus != "insufficient_information" {
		return errors.New("expect-status must be known_match, no_known_match or insufficient_information")
	}
	key, err := base64.StdEncoding.DecodeString(*publicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	c, err := client.New(*feedURL, ed25519.PublicKey(key))
	if err != nil {
		return err
	}
	var q client.Identity
	if err = json.Unmarshal([]byte(*queryJSON), &q); err != nil {
		return fmt.Errorf("decode query: %w", err)
	}
	if err = q.Normalize(); err != nil {
		return err
	}
	var previous *client.Snapshot
	var previousSequence int64
	saved, err := client.Load(*cachePath, key)
	if err == nil {
		previous = &saved
		m, verifyErr := saved.Verify(key)
		if verifyErr != nil {
			return verifyErr
		}
		previousSequence = m.Sequence
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load existing cache: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	snapshot, err := c.Update(ctx, previous)
	if err != nil {
		return fmt.Errorf("verified client update: %w", err)
	}
	local, err := snapshot.Query(q, key)
	if err != nil {
		return err
	}
	if *expectedStatus != "" && local.Status != *expectedStatus {
		return fmt.Errorf("expected %s, got %s", *expectedStatus, local.Status)
	}
	u, err := url.Parse(strings.TrimSuffix(strings.TrimRight(*feedURL, "/"), "/feed") + "/v1/query")
	if err != nil {
		return err
	}
	hostedHTTP := netfetch.New([]string{u.Hostname()}, "")
	if err = hostedHTTP.CheckURL(u.String()); err != nil {
		return err
	}
	body, err := json.Marshal(q)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := os.Getenv("ZOLI_READINESS_API_KEY"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// Keep query credentials on the configured endpoint; feed downloads remain public.
	hostedHTTP.HTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := hostedHTTP.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("hosted lookup: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("hosted lookup HTTP %d", res.StatusCode)
	}
	var hosted client.QueryResponse
	if err = json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(&hosted); err != nil {
		return fmt.Errorf("decode hosted lookup: %w", err)
	}
	if hosted.Sequence != local.Sequence {
		return fmt.Errorf("publication changed during comparison (local %d, hosted %d); retry", local.Sequence, hosted.Sequence)
	}
	localJSON, err := json.Marshal(local)
	if err != nil {
		return err
	}
	hostedJSON, err := json.Marshal(hosted)
	if err != nil {
		return err
	}
	if !bytes.Equal(localJSON, hostedJSON) {
		return errors.New("hosted and local lookups differ; inspect the query, freshness and publication")
	}
	if err = snapshot.Save(*cachePath); err != nil {
		return err
	}
	reloaded, err := client.Load(*cachePath, key)
	if err != nil {
		return fmt.Errorf("reload saved cache: %w", err)
	}
	reloadedQuery, err := reloaded.Query(q, key)
	if err != nil {
		return err
	}
	reloadedJSON, err := json.Marshal(reloadedQuery)
	if err != nil {
		return err
	}
	if !bytes.Equal(localJSON, reloadedJSON) {
		return errors.New("query changed after cache reload")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"previous_sequence": previousSequence, "sequence": local.Sequence,
		"record_count": len(snapshot.Records), "status": local.Status, "freshness": local.Freshness,
		"hosted_agreement": true, "cache_reload_verified": true,
	})
}
