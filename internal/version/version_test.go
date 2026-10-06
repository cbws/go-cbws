package version

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolve(t *testing.T) {
	tests := []struct {
		name    string
		info    *debug.BuildInfo
		release string
		want    string
	}{
		{
			name: "dependency",
			info: &debug.BuildInfo{
				Main: debug.Module{Path: "cbws.xyz/cbws", Version: "(devel)"},
				Deps: []*debug.Module{{Path: modulePath, Version: "v1.18.0"}},
			},
			release: "1.17.0",
			want:    "1.18.0",
		},
		{
			name: "pseudo-version",
			info: &debug.BuildInfo{
				Deps: []*debug.Module{{Path: modulePath, Version: "v1.18.1-0.20261006120000-abcdef123456"}},
			},
			release: "1.18.0",
			want:    "1.18.1-0.20261006120000-abcdef123456",
		},
		{
			name: "replaced by another version",
			info: &debug.BuildInfo{
				Deps: []*debug.Module{{
					Path:    modulePath,
					Version: "v1.18.0",
					Replace: &debug.Module{Path: "example.com/fork/sdk", Version: "v1.18.0-fork.1"},
				}},
			},
			want: "1.18.0-fork.1",
		},
		{
			name: "replaced by a local directory",
			info: &debug.BuildInfo{
				Deps: []*debug.Module{{
					Path:    modulePath,
					Version: "v1.18.0",
					Replace: &debug.Module{Path: "../go-cbws"},
				}},
			},
			release: "1.18.0",
			want:    "1.18.0",
		},
		{
			name: "main module stamped from version control",
			info: &debug.BuildInfo{
				Main: debug.Module{Path: modulePath, Version: "v1.18.0"},
			},
			want: "1.18.0",
		},
		{
			name: "main module outside version control",
			info: &debug.BuildInfo{
				Main: debug.Module{Path: modulePath, Version: "(devel)"},
			},
			release: "1.18.0",
			want:    "1.18.0",
		},
		{
			name:    "no build information",
			release: "1.18.0",
			want:    "1.18.0",
		},
		{
			name: "nothing known",
			info: &debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}},
			want: unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resolve(tt.info, tt.release))
		})
	}
}

func TestGetNamesAVersion(t *testing.T) {
	assert.NotEmpty(t, Get())
}
