package main

import (
	"bufio"
	"fmt"
	"github.com/wow-look-at-my/go-containers/set"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

type key struct {
	layer int
	path  string
}

// finalView returns the files a container sees: the last writer of each path that no later whiteout or opaque dir hides.
func finalView(es []Entry) map[string]Entry {
	wh := map[string]int{}
	op := map[string]int{}
	last := map[string]Entry{}
	for _, e := range es {
		switch e.Kind {
		case 'w':
			wh[e.Path] = max(wh[e.Path], e.Layer+1)
		case 'o':
			op[e.Path] = max(op[e.Path], e.Layer+1)
		default:
			if cur, ok := last[e.Path]; !ok || e.Layer >= cur.Layer {
				last[e.Path] = e
			}
		}
	}
	view := map[string]Entry{}
	for p, e := range last {
		if !hidden(p, e.Layer, wh, op) {
			view[p] = e
		}
	}
	return view
}

// hidden reports whether a later layer whites out p or one of its ancestors, or marks an ancestor opaque.
// The maps hold the layer index plus one, so a missing key reads as zero.
func hidden(p string, layer int, wh, op map[string]int) bool {
	for q := p; ; q = path.Dir(q) {
		if wh[q] > layer+1 {
			return true
		}
		if q != p && op[q] > layer+1 {
			return true
		}
		if q == "." || q == "/" {
			return false
		}
	}
}

// Bytes is an uncompressed size and a share of the compressed layer streams.
type Bytes struct{ Raw, Packed int64 }

func mb(n int64) int64 { return n >> 20 }

// DupGroup is a set of identical files in the final view.
type DupGroup struct {
	Hash   string
	Size   int64
	Packed     int64
	Paths  []string
	Layers []int
}

func (g DupGroup) reclaim() Bytes {
	n := int64(len(g.Paths) - 1)
	return Bytes{Raw: n * g.Size, Packed: n * g.Packed}
}

func (g DupGroup) sameLayer() bool {
	for _, l := range g.Layers {
		if l != g.Layers[0] {
			return false
		}
	}
	return true
}

func dupGroups(view map[string]Entry) []DupGroup {
	groups := map[string]*DupGroup{}
	for _, e := range view {
		if e.Kind != 'f' || e.Size == 0 {
			continue
		}
		g := groups[e.Hash]
		if g == nil {
			g = &DupGroup{Hash: e.Hash, Size: e.Size, Packed: e.Packed}
			groups[e.Hash] = g
		}
		g.Paths = append(g.Paths, e.Path)
		g.Layers = append(g.Layers, e.Layer)
	}
	var out []DupGroup
	for _, g := range groups {
		if len(g.Paths) > 1 {
			sort.Strings(g.Paths)
			sort.Ints(g.Layers)
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := out[i].reclaim().Raw, out[j].reclaim().Raw
		if ri != rj {
			return ri > rj
		}
		return out[i].Hash < out[j].Hash
	})
	return out
}

// Rule names the files whose path matches Re.
type Rule struct {
	Name string
	Re   *regexp.Regexp
}

// parseRules reads "name<TAB>regex" lines. Blank lines and lines that start with # are skipped.
func parseRules(r io.Reader) ([]Rule, error) {
	var out []Rule
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, expr, ok := strings.Cut(line, "\t")
		if !ok {
			return nil, fmt.Errorf("rules line %d: want name<TAB>regex", n)
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("rules line %d: %w", n, err)
		}
		out = append(out, Rule{name, re})
	}
	return out, sc.Err()
}

var defaultRules = mustRules(`python packages	(^|/)(site|dist)-packages/
CUDA toolkit	^usr/local/cuda
NVIDIA tools in /opt/nvidia	^opt/nvidia/
/usr/lib	^usr/lib/
/usr/share	^usr/share/
/usr/bin, /usr/sbin, /usr/libexec	^usr/(bin|sbin|libexec)/
/usr/include	^usr/include/
/usr/local	^usr/local/
/opt	^opt/
/root	^root/
everything else	.
`)

func mustRules(s string) []Rule {
	rs, err := parseRules(strings.NewReader(s))
	if err != nil {
		panic(err)
	}
	return rs
}

func classify(rs []Rule, p string) string {
	for _, r := range rs {
		if r.Re.MatchString(p) {
			return r.Name
		}
	}
	return ""
}

var pkgRe = regexp.MustCompile(`(?:^|/)(?:site|dist)-packages/([^/]+)`)

// pythonPackage returns the top-level site-packages entry a path belongs to, or "".
func pythonPackage(p string) string {
	m := pkgRe.FindStringSubmatch(p)
	if m == nil {
		return ""
	}
	return m[1]
}

type row struct {
	name string
	b    Bytes
}

func sortedRows(m map[string]*Bytes) []row {
	var out []row
	for k, v := range m {
		out = append(out, row{k, *v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].b.Packed != out[j].b.Packed {
			return out[i].b.Packed > out[j].b.Packed
		}
		return out[i].name < out[j].name
	})
	return out
}

func bump(m map[string]*Bytes, k string, b Bytes) {
	if m[k] == nil {
		m[k] = &Bytes{}
	}
	m[k].Raw += b.Raw
	m[k].Packed += b.Packed
}

func entryBytes(e Entry) Bytes { return Bytes{e.Size, e.Packed} }

func printRows(w io.Writer, title string, rows []row, limit int) {
	var t Bytes
	fmt.Fprintf(w, "\n## %s\n%8s %8s  %s\n", title, "pack MB", "raw MB", "what")
	for i, r := range rows {
		if limit == 0 || i < limit {
			fmt.Fprintf(w, "%8d %8d  %s\n", mb(r.b.Packed), mb(r.b.Raw), r.name)
		}
		t.Raw += r.b.Raw
		t.Packed += r.b.Packed
	}
	if limit > 0 && len(rows) > limit {
		fmt.Fprintf(w, "%8s %8s  (%d more rows in the total)\n", "", "", len(rows)-limit)
	}
	fmt.Fprintf(w, "%8d %8d  TOTAL\n", mb(t.Packed), mb(t.Raw))
}

// Options picks how report groups files. Drop lists files a planned change deletes, kept out of every other table.
type Options struct {
	Rules  []Rule
	Drop   []Rule
	Labels []string
	Top    int
}

// report writes the dead-byte, duplicate, dropped and remaining-content tables.
func report(w io.Writer, es []Entry, o Options) {
	if o.Rules == nil {
		o.Rules = defaultRules
	}
	view := finalView(es)
	live := set.New[key]()
	for _, e := range view {
		live.Add(key{e.Layer, e.Path})
	}
	dropped := func(p string) bool { return classify(o.Drop, p) != "" }

	dead := map[string]*Bytes{}
	for _, e := range es {
		if e.Kind != 'f' || live.Contains(key{e.Layer, e.Path}) {
			continue
		}
		k := "shadowed or deleted by a later layer: " + label(o.Labels, e.Layer)
		if strings.Contains(e.Path, "__pycache__/") {
			k = ".pyc deleted by a later layer"
		}
		bump(dead, k, entryBytes(e))
	}
	printRows(w, "Dead bytes: in a layer, not visible in the container", sortedRows(dead), o.Top)

	dup := map[string]*Bytes{}
	var shown []DupGroup
	for _, g := range dupGroups(view) {
		if dropped(g.Paths[0]) {
			continue
		}
		k := "across layers (a symlink fixes it)"
		if g.sameLayer() {
			k = "inside one layer (a hardlink fixes it)"
		}
		bump(dup, k, g.reclaim())
		shown = append(shown, g)
	}
	printRows(w, "Duplicate content in the final view, bytes reclaimable", sortedRows(dup), 0)
	fmt.Fprintf(w, "\nLargest duplicate groups:\n")
	for i, g := range shown {
		if i == o.Top {
			break
		}
		fmt.Fprintf(w, "%6d MB  x%d  layers %v  %s\n", mb(g.reclaim().Raw), len(g.Paths), uniq(g.Layers), strings.Join(g.Paths, "  "))
	}

	drop := map[string]*Bytes{}
	keep := map[string]*Bytes{}
	pkgs := map[string]*Bytes{}
	for _, e := range view {
		if e.Kind != 'f' {
			continue
		}
		if name := classify(o.Drop, e.Path); name != "" {
			bump(drop, name, entryBytes(e))
			continue
		}
		bump(keep, classify(o.Rules, e.Path), entryBytes(e))
		if p := pythonPackage(e.Path); p != "" {
			bump(pkgs, p, entryBytes(e))
		}
	}
	if len(o.Drop) > 0 {
		printRows(w, "Files the --drop rules delete", sortedRows(drop), 0)
	}
	printRows(w, "Remaining files by category", sortedRows(keep), 0)
	if len(pkgs) > 0 {
		printRows(w, "Remaining python packages", sortedRows(pkgs), o.Top)
	}
}

// reportLayers compares each layer's tar stream compressed again with the blob the registry holds.
// Both sizes match only when the codec and level match the ones the image was pushed with.
func reportLayers(w io.Writer, layers []descriptor, stats []LayerStat, labels []string) {
	fmt.Fprintf(w, "\n## Layers: the tar stream compressed again vs the registry blob\n%8s %8s %7s  %s\n", "pack MB", "blob MB", "diff", "layer")
	var pack, blob int64
	for i, d := range layers {
		if i >= len(stats) {
			break
		}
		s := stats[i]
		pack += s.Packed
		blob += d.Size
		fmt.Fprintf(w, "%8d %8d %7s  %s (%s level %d)\n", mb(s.Packed), mb(d.Size), pct(s.Packed, d.Size), label(labels, i), s.Codec, s.Level)
	}
	fmt.Fprintf(w, "%8d %8d %7s  TOTAL\n", mb(pack), mb(blob), pct(pack, blob))
}

func pct(a, b int64) string {
	if b == 0 {
		return "-"
	}
	return fmt.Sprintf("%+.1f%%", 100*float64(a-b)/float64(b))
}

func label(labels []string, l int) string {
	if l < len(labels) {
		return fmt.Sprintf("layer %d %s", l, labels[l])
	}
	return fmt.Sprintf("layer %d", l)
}

func uniq(ls []int) []int {
	var out []int
	for i, l := range ls {
		if i == 0 || l != ls[i-1] {
			out = append(out, l)
		}
	}
	return out
}
