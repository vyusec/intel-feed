package netfetch

import (
	"net"
	"testing"
)

func TestDestinationPolicy(t *testing.T) {
	c := New([]string{"pypi.org"}, "")
	for _, u := range []string{"http://pypi.org/data", "https://pypi.org:8443/data", "https://user:password@pypi.org/data", "https://127.0.0.1/data", "https://pypi.org.evil.example/data"} {
		if c.CheckURL(u) == nil {
			t.Fatal("accepted", u)
		}
	}
	if c.CheckURL("https://pypi.org/data") != nil {
		t.Fatal("rejected registry")
	}
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.1.1", "::1", "fc00::1"} {
		if publicIP(net.ParseIP(s)) {
			t.Fatal("accepted private address", s)
		}
	}
}
