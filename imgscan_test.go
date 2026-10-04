package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type member struct {
	name, body, link string
	kind             byte
}

func layerBytes(t *testing.T, ms ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, m := range ms {
		h := &tar.Header{Name: m.name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(m.body))}
		switch m.kind {
		case 'd':
			h.Typeflag, h.Size = tar.TypeDir, 0
		case 'l':
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, m.link, 0
		case 'h':
			h.Typeflag, h.Linkname, h.Size = tar.TypeLink, m.link, 0
		}
		require.NoError(t, tw.WriteHeader(h))
		if h.Size > 0 {
			_, err := tw.Write([]byte(m.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func scan(t *testing.T, layer int, ms ...member) []Entry {
	t.Helper()
	es, err := scanLayer(bytes.NewReader(layerBytes(t, ms...)), layer)
	require.NoError(t, err)
	return es
}

func TestScanLayerKinds(t *testing.T) {
	es := scan(t, 3,
		member{name: "./usr/", kind: 'd'},
		member{name: "./usr/a", body: "hello"},
		member{name: "usr/l", link: "a", kind: 'l'},
		member{name: "usr/h", link: "./usr/a", kind: 'h'},
		member{name: "usr/.wh.gone"},
		member{name: "opt/.wh..wh..opq"},
	)
	require.Len(t, es, 5)
	assert.Equal(t, Entry{Layer: 3, Kind: 'f', Path: "usr/a", Size: 5, Gz: es[0].Gz, Hash: es[0].Hash}, es[0])
	assert.Positive(t, es[0].Gz)
	assert.Equal(t, Entry{Layer: 3, Kind: 'l', Path: "usr/l", Link: "a"}, es[1])
	assert.Equal(t, Entry{Layer: 3, Kind: 'h', Path: "usr/h", Link: "usr/a"}, es[2])
	assert.Equal(t, Entry{Layer: 3, Kind: 'w', Path: "usr/gone"}, es[3])
	assert.Equal(t, Entry{Layer: 3, Kind: 'o', Path: "opt"}, es[4])
}

func TestScanLayerZstd(t *testing.T) {
	ms := []member{{name: "usr/a", body: "hello"}, {name: "usr/l", link: "a", kind: 'l'}}
	gzLayer := layerBytes(t, ms...)
	gz, err := gzip.NewReader(bytes.NewReader(gzLayer))
	require.NoError(t, err)
	var zbuf bytes.Buffer
	zw, err := zstd.NewWriter(&zbuf)
	require.NoError(t, err)
	_, err = io.Copy(zw, gz)
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	fromZstd, err := scanLayer(&zbuf, 2)
	require.NoError(t, err)
	assert.Equal(t, scan(t, 2, ms...), fromZstd)
}

func TestScanLayerErrors(t *testing.T) {
	_, err := scanLayer(strings.NewReader("not gzip"), 0)
	assert.ErrorContains(t, err, "gzip")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("not a tar archive, but long enough to need a header block....................................................................................................................................................................................................................................................................................................................................................................................................................................................................."))
	require.NoError(t, gz.Close())
	_, err = scanLayer(&buf, 0)
	assert.ErrorContains(t, err, "tar")
}

func TestEntriesRoundTrip(t *testing.T) {
	es := scan(t, 1, member{name: "a b/c", body: "x"}, member{name: "s", link: "a b/c", kind: 'l'})
	var buf bytes.Buffer
	require.NoError(t, writeEntries(&buf, es))
	back, err := readEntries(&buf)
	require.NoError(t, err)
	assert.Equal(t, es, back)
	_, err = readEntries(strings.NewReader("garbage\n"))
	assert.Error(t, err)
	_, err = readEntries(strings.NewReader("x\tf\t1\t1\th\tp\t\n"))
	assert.Error(t, err)
}

func TestFinalView(t *testing.T) {
	var es []Entry
	es = append(es, scan(t, 0,
		member{name: "keep", body: "k"},
		member{name: "over", body: "old"},
		member{name: "dir/x", body: "x"},
		member{name: "opq/y", body: "y"},
	)...)
	es = append(es, scan(t, 1,
		member{name: "over", body: "new"},
		member{name: ".wh.dir"},
		member{name: "opq/.wh..wh..opq"},
		member{name: "opq/z", body: "z"},
	)...)
	es = append(es, scan(t, 2, member{name: "dir/back", body: "b"})...)
	view := finalView(es)
	var paths []string
	for p := range view {
		paths = append(paths, p)
	}
	assert.ElementsMatch(t, []string{"keep", "over", "opq/z", "dir/back"}, paths)
	assert.Equal(t, 1, view["over"].Layer)
}

func TestDupGroups(t *testing.T) {
	es := append(scan(t, 0, member{name: "a", body: "same"}, member{name: "b", body: "same"}, member{name: "e"}),
		scan(t, 1, member{name: "c", body: "same"}, member{name: "d", body: "other"})...)
	gs := dupGroups(finalView(es))
	require.Len(t, gs, 1)
	assert.Equal(t, []string{"a", "b", "c"}, gs[0].Paths)
	assert.False(t, gs[0].sameLayer())
	assert.Equal(t, int64(8), gs[0].reclaim().Raw)
	assert.Equal(t, []int{0, 1}, uniq(gs[0].Layers))
}

func TestParseRules(t *testing.T) {
	rs, err := parseRules(strings.NewReader("# c\n\nlibs\t^usr/lib/\n"))
	require.NoError(t, err)
	assert.Equal(t, "libs", classify(rs, "usr/lib/x"))
	assert.Equal(t, "", classify(rs, "etc/x"))
	_, err = parseRules(strings.NewReader("no tab\n"))
	assert.ErrorContains(t, err, "line 1")
	_, err = parseRules(strings.NewReader("bad\t(\n"))
	assert.ErrorContains(t, err, "line 1")
	assert.Panics(t, func() { mustRules("bad\t(") })
}

func TestReport(t *testing.T) {
	es := append(scan(t, 0,
		member{name: "usr/lib/a", body: "dup!"},
		member{name: "usr/lib/b", body: "dup!"},
		member{name: "opt/venv/lib/python3.12/site-packages/torch/x.so", body: "torch"},
		member{name: "opt/venv/lib/python3.12/site-packages/junk/y", body: "junk"},
		member{name: "p/__pycache__/m.pyc", body: "pyc"},
		member{name: "gone", body: "dead"},
		member{name: "lib/one.so", body: "twin"},
		member{name: "lib/two.so", body: "twin"},
	), scan(t, 1,
		member{name: "p/.wh.__pycache__"},
		member{name: ".wh.gone"},
		member{name: "etc/c", body: "dup!"},
	)...)
	drop := mustRules("junk\tsite-packages/junk/\n")
	var buf bytes.Buffer
	report(&buf, es, Options{Drop: drop, Labels: []string{"RUN base", "RUN cleanup"}, Top: 5})
	out := buf.String()
	assert.Contains(t, out, ".pyc deleted by a later layer")
	assert.Contains(t, out, "layer 0 RUN base")
	assert.Contains(t, out, "inside one layer (a hardlink fixes it)")
	assert.Contains(t, out, "across layers (a symlink fixes it)")
	assert.Contains(t, out, "x3")
	assert.Contains(t, out, "Files the --drop rules delete")
	assert.Contains(t, out, "python packages")
	assert.Contains(t, out, "torch")
	assert.NotContains(t, strings.SplitN(out, "Remaining python packages", 2)[1], "junk")
	assert.Equal(t, "layer 9", label(nil, 9))

	buf.Reset()
	report(&buf, es, Options{Top: 1})
	assert.Contains(t, buf.String(), "more rows in the total")
}

func TestSplitRef(t *testing.T) {
	for in, want := range map[string][2]string{
		"org/img:dev":           {"org/img", "dev"},
		"org/img@sha256:abc":    {"org/img", "sha256:abc"},
		"org/img":               {"org/img", "latest"},
		"host:5000/org/img":     {"host:5000/org/img", "latest"},
		"host:5000/org/img:tag": {"host:5000/org/img", "tag"},
	} {
		repo, ref := splitRef(in)
		assert.Equal(t, want, [2]string{repo, ref}, in)
	}
	assert.Equal(t, "RUN apt-get install x", shortCmd("RUN |2 A=1 B= /bin/sh -c apt-get   install x"))
	assert.Len(t, shortCmd(strings.Repeat("x", 200)), 90)
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// fakeRegistry serves one multi-arch image with layers under /v2/org/img and a token endpoint.
func fakeRegistry(t *testing.T) *httptest.Server {
	t.Helper()
	l0 := layerBytes(t, member{name: "usr/lib/a", body: "same"}, member{name: "tmp/x", body: "dead"})
	l1 := layerBytes(t, member{name: "opt/b", body: "same"}, member{name: "tmp/.wh.x"})
	cfg, _ := json.Marshal(map[string]any{"history": []map[string]any{
		{"created_by": "/bin/sh -c #(nop) ADD file:abc in /"},
		{"created_by": "ENV X=1", "empty_layer": true},
		{"created_by": "RUN |1 A=b /bin/sh -c rm /tmp/x"},
	}})
	man, _ := json.Marshal(map[string]any{
		"config": map[string]any{"digest": digest(cfg)},
		"layers": []map[string]any{{"digest": digest(l0), "size": len(l0)}, {"digest": digest(l1), "size": len(l1)}},
	})
	idx, _ := json.Marshal(map[string]any{"manifests": []map[string]any{
		{"digest": "sha256:arm", "platform": map[string]string{"architecture": "arm64", "os": "linux"}},
		{"digest": digest(man), "platform": map[string]string{"architecture": "amd64", "os": "linux"}},
	}})
	blobs := map[string][]byte{
		"/v2/org/img/manifests/dev":            idx,
		"/v2/org/img/manifests/" + digest(man): man,
		"/v2/org/img/blobs/" + digest(cfg):     cfg,
		"/v2/org/img/blobs/" + digest(l0):      l0,
		"/v2/org/img/blobs/" + digest(l1):      l1,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = w.Write([]byte(`{"token":"t0k"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer t0k" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		b, ok := blobs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestCLIEndToEnd(t *testing.T) {
	srv := fakeRegistry(t)
	dir := t.TempDir()
	cache := filepath.Join(dir, "entries.tsv")
	rules := filepath.Join(dir, "rules")
	require.NoError(t, os.WriteFile(rules, []byte("libs\t^usr/lib/\nrest\t.\n"), 0o644))
	out, err := runCLI(t, "org/img:dev", "--registry", srv.URL, "--entries", cache, "--rules", rules, "--drop", rules)
	require.NoError(t, err)
	assert.Contains(t, out, "org/img:dev linux/amd64: 2 layers")
	assert.Contains(t, out, "layer 0 ADD file:abc in /")
	_, err = os.Stat(cache)
	require.NoError(t, err)

	again, err := runCLI(t, "org/img:dev", "--registry", srv.URL, "--entries", cache)
	require.NoError(t, err)
	assert.Contains(t, again, "across layers (a symlink fixes it)")
}

func TestCLIErrors(t *testing.T) {
	srv := fakeRegistry(t)
	_, err := runCLI(t, "org/img:dev", "--registry", srv.URL, "--arch", "s390x")
	assert.ErrorContains(t, err, "no linux/s390x manifest")
	_, err = runCLI(t, "org/img:nope", "--registry", srv.URL)
	assert.ErrorContains(t, err, "404")
	_, err = runCLI(t, "org/img:dev", "--registry", srv.URL, "--token-url", srv.URL+"/missing")
	assert.ErrorContains(t, err, "token")
	_, err = runCLI(t, "org/img:dev", "--registry", srv.URL, "--rules", "/does/not/exist")
	assert.Error(t, err)
	_, err = runCLI(t, "org/img:dev", "--registry", srv.URL, "--drop", "/does/not/exist")
	assert.Error(t, err)
	_, err = runCLI(t, "org/img:dev", "--registry", srv.URL, "--entries", "/does/not/exist/dir/e.tsv")
	assert.Error(t, err)
	_, err = runCLI(t, "org/img:dev", "--registry", "http://127.0.0.1:1")
	assert.Error(t, err)
	_, err = runCLI(t)
	assert.Error(t, err)
}

func TestScanAllReportsBadBlob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not gzip"))
	}))
	defer srv.Close()
	reg := &Registry{Base: srv.URL, Repo: "o/i", HTTP: srv.Client()}
	_, err := scanAll(reg, manifest{Layers: []descriptor{{Digest: "sha256:a"}}}, 0, &bytes.Buffer{})
	assert.ErrorContains(t, err, "gzip")
	_, err = scanAll(&Registry{Base: "http://127.0.0.1:1", Repo: "o/i", HTTP: srv.Client()}, manifest{Layers: []descriptor{{Digest: "sha256:a"}}}, 1, &bytes.Buffer{})
	assert.Error(t, err)
}
