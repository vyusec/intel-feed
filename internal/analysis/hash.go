// SPDX-License-Identifier: Apache-2.0
package analysis

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
)

func verify512(b []byte, integrity string) error {
	if integrity == "" {
		return nil
	}
	expected, err := base64.StdEncoding.DecodeString(integrity)
	sum := sha512.Sum512(b)
	if err != nil || subtle.ConstantTimeCompare(expected, sum[:]) != 1 {
		return errors.New("artifact sha512 integrity mismatch")
	}
	return nil
}
func escapeName(s string) string { return url.PathEscape(s) }
