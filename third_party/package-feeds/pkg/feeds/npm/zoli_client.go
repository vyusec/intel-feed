// Copyright 2026 Zoli contributors. Licensed under Apache-2.0.
// Zoli addition: inject an allowlisted, bounded HTTP client.
package npm

import "net/http"

func (f *Feed) SetClient(c *http.Client) { f.client = c }
