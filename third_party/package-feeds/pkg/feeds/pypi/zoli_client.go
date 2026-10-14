// Copyright 2026 Zoli contributors. Licensed under Apache-2.0.
// Zoli addition: inject an allowlisted, bounded HTTP client before starting feeds.
package pypi

import "net/http"

func SetClient(c *http.Client) { httpClient = c }
