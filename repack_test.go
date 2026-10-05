package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func elfLike(seed byte) string {
	return "\x7fELF" + noise(40<<10, 9) + noise(8<<10, seed)
}

func TestRepackGroupingBeatsPathOrder(t *testing.T) {
	gzLayer := layerBytes(t,
		member{name: "lib/", kind: 'd'},
		member{name: "lib/a.so", body: elfLike(1)},
		member{name: "lib/a.txt", body: noise(40<<10, 2)},
		member{name: "lib/b.so", body: elfLike(3)},
		member{name: "lib/b.txt", body: noise(40<<10, 4)},
		member{name: "lib/c.so", body: elfLike(5)},
		member{name: "lib/copy.so", body: elfLike(5)},
	)
	s, err := repackLayer(bytes.NewReader(gzLayer), 0, ScanOptions{}, t.TempDir())
	require.NoError(t, err)
	assert.Less(t, s.Typed, s.Path, "grouping by type puts similar bodies inside the window")
	assert.Less(t, s.Linked, s.Typed, "a hardlink replaces the identical body")
}

// The rewritten tar must extract to the same files: every hardlink after the file it names, every body kept.
func TestRepackWritesAValidTar(t *testing.T) {
	gzLayer := layerBytes(t,
		member{name: "z/", kind: 'd'},
		member{name: "z/b.so", body: elfLike(1)},
		member{name: "a/x.txt", body: "text"},
		member{name: "z/a.so", body: elfLike(1)},
		member{name: "a/link", link: "x.txt", kind: 'l'},
		member{name: "a/hard", link: "z/b.so", kind: 'h'},
		member{name: "a/.wh.gone"},
	)
	plain, _, err := decompress(bytes.NewReader(gzLayer), 0)
	require.NoError(t, err)
	f, err := os.CreateTemp(t.TempDir(), "bodies")
	require.NoError(t, err)
	defer f.Close()
	ms, err := readMembers(tar.NewReader(plain), f, 0)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, writeMembers(&buf, typedOrder(ms), f, true))
	tr := tar.NewReader(&buf)
	bodies := map[string][32]byte{}
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		names = append(names, h.Name)
		switch h.Typeflag {
		case tar.TypeReg:
			b, err := io.ReadAll(tr)
			require.NoError(t, err)
			bodies[h.Name] = sha256.Sum256(b)
		case tar.TypeLink:
			target, ok := bodies[h.Linkname]
			require.True(t, ok, "%s links to %s before it is written", h.Name, h.Linkname)
			bodies[h.Name] = target
		}
	}
	sort.Strings(names)
	assert.Equal(t, []string{"a/.wh.gone", "a/hard", "a/link", "a/x.txt", "z/", "z/a.so", "z/b.so"}, names)
	assert.Equal(t, bodies["z/b.so"], bodies["z/a.so"])
	assert.Equal(t, bodies["z/b.so"], bodies["a/hard"])
	assert.Equal(t, sha256.Sum256([]byte("text")), bodies["a/x.txt"])
}

func TestRepackCLI(t *testing.T) {
	srv := fakeRegistry(t)
	cmd := newRootCmd()
	cmd.AddCommand(newRepackCmd())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"repack", "org/img:dev", "--registry", srv.URL, "--tmp", t.TempDir()})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "layer 0 ADD file:abc in /")
	assert.Contains(t, out.String(), "typed vs path:")

	cmd = newRootCmd()
	cmd.AddCommand(newRepackCmd())
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"repack", "org/img:dev", "--registry", srv.URL, "--codec", "lz4"})
	assert.ErrorContains(t, cmd.Execute(), "want zstd or gzip")
}
