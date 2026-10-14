module zoli.dev/intel-feed

go 1.26

require (
	deps.dev/util/semver v0.0.0
	github.com/lib/pq v1.10.9
	github.com/ossf/package-feeds v0.0.0
	golang.org/x/sys v0.39.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
)

replace deps.dev/util/semver => ./third_party/semver

replace github.com/ossf/package-feeds => ./third_party/package-feeds
