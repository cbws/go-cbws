// Package version reports which release of the SDK a program was built with.
package version

import (
	"runtime/debug"
	"strings"
	"sync"
)

// modulePath is the SDK's module path, as it appears in a program's build
// information.
const modulePath = "go.cbws.cloud/sdk"

// Release is the SDK release this source belongs to, without a leading "v".
// It is the answer only for builds that carry no module information; the
// go command records the exact version, pseudo-versions included, and that
// takes precedence. Empty means unknown.
const Release = ""

// unknown is reported when neither the build information nor Release names
// a version.
const unknown = "unknown"

var resolved = sync.OnceValue(func() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		info = nil
	}

	return resolve(info, Release)
})

// Get returns the SDK version without a leading "v", for example "1.18.0".
func Get() string {
	return resolved()
}

// resolve finds the SDK in info, either as a dependency or as the main
// module when the SDK's own packages are being tested, and falls back to
// release when info names no usable version.
func resolve(info *debug.BuildInfo, release string) string {
	if v := fromBuildInfo(info); v != "" {
		return v
	}
	if release != "" {
		return release
	}

	return unknown
}

func fromBuildInfo(info *debug.BuildInfo) string {
	if info == nil {
		return ""
	}

	if info.Main.Path == modulePath {
		return usable(&info.Main)
	}

	for _, dep := range info.Deps {
		if dep.Path == modulePath {
			return usable(dep)
		}
	}

	return ""
}

// usable returns the version of m, following a replacement. A replacement by
// a local directory has no version, and a main module built outside version
// control is "(devel)"; neither says which release it is.
func usable(m *debug.Module) string {
	if m.Replace != nil {
		m = m.Replace
	}

	if m.Version == "" || m.Version == "(devel)" {
		return ""
	}

	return strings.TrimPrefix(m.Version, "v")
}
