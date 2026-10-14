package discovery

import "testing"

func TestNameResemblance(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"react", "react", false}, {"raect", "react", false}, {"reac", "react", true}, {"reqct", "react", true}, {"reactt", "react", true}, {"express", "react", false}} {
		if got := editDistanceOne(c.a, c.b); got != c.want {
			t.Fatalf("%s %s %v", c.a, c.b, got)
		}
	}
}
