package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Entry is one tar member of one layer. Kind is f (file), l (symlink), h
// (hardlink), w (whiteout), o (opaque dir).
type Entry struct {
	Layer  int
	Kind   byte
	Path   string
	Size   int64
	Packed int64
	Hash   string
	Link   string
}

// Codec is a layer blob compression.
type Codec string

const (
	Zstd Codec = "zstd"
	Gzip Codec = "gzip"
)

// ScanOptions picks how a layer's tar stream is compressed again.
type ScanOptions struct {
	Codec Codec
	Level int
}

// LayerStat is the compressed size of one layer's whole tar stream.
type LayerStat struct {
	Layer    int
	Codec    Codec
	Level    int
	Packed   int64
	Overhead int64
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

// decompress picks gzip or zstd from the stream's magic bytes, so a mislabeled media type cannot mislead it.
func decompress(r io.Reader, layer int) (io.Reader, Codec, error) {
	br := bufio.NewReader(r)
	head, err := br.Peek(len(zstdMagic))
	if err == nil && bytes.Equal(head, zstdMagic) {
		zr, err := zstd.NewReader(br, zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, "", fmt.Errorf("layer %d: zstd: %w", layer, err)
		}
		return zr.IOReadCloser(), Zstd, nil
	}
	gz, err := gzip.NewReader(br)
	if err != nil {
		return nil, "", fmt.Errorf("layer %d: neither zstd nor gzip: %w", layer, err)
	}
	return gz, Gzip, nil
}

// meter compresses a tar stream as one stream, the way a registry blob holds
// it, and counts the output.
type meter struct {
	w     io.WriteCloser
	flush func() error
	out   countWriter
	last  int64
}

func newMeter(c Codec, level int) (*meter, error) {
	m := &meter{}
	switch c {
	case Zstd:
		opts := []zstd.EOption{zstd.WithEncoderConcurrency(1)}
		if level != 0 {
			opts = append(opts, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)))
		}
		zw, err := zstd.NewWriter(&m.out, opts...)
		if err != nil {
			return nil, err
		}
		m.w, m.flush = zw, zw.Flush
	case Gzip:
		if level == 0 {
			level = gzip.DefaultCompression
		}
		gw, err := gzip.NewWriterLevel(&m.out, level)
		if err != nil {
			return nil, err
		}
		m.w, m.flush = gw, gw.Flush
	default:
		return nil, fmt.Errorf("unknown codec %q: want zstd or gzip", c)
	}
	return m, nil
}

func (m *meter) Write(p []byte) (int, error) { return m.w.Write(p) }

// mark flushes and returns the compressed bytes written since the mark.
func (m *meter) mark() (int64, error) {
	if err := m.flush(); err != nil {
		return 0, err
	}
	n := m.out.n - m.last
	m.last = m.out.n
	return n, nil
}

// finish ends the stream and returns the bytes written since the mark.
func (m *meter) finish() (int64, error) {
	if err := m.w.Close(); err != nil {
		return 0, err
	}
	n := m.out.n - m.last
	m.last = m.out.n
	return n, nil
}

// scanLayer reads one gzip or zstd layer. It hashes each file and compresses the tar stream again to give each entry its packed share.
func scanLayer(r io.Reader, layer int, o ScanOptions) ([]Entry, LayerStat, error) {
	plain, codec, err := decompress(r, layer)
	if err != nil {
		return nil, LayerStat{}, err
	}
	if o.Codec != "" {
		codec = o.Codec
	}
	m, err := newMeter(codec, o.Level)
	if err != nil {
		return nil, LayerStat{}, err
	}
	stat := LayerStat{Layer: layer, Codec: codec, Level: o.Level}
	tr := tar.NewReader(io.TeeReader(plain, m))
	var out []Entry
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, stat, fmt.Errorf("layer %d: tar: %w", layer, err)
		}
		e, ok, err := readMember(tr, h, layer)
		if err != nil {
			return nil, stat, err
		}
		n, err := m.mark()
		if err != nil {
			return nil, stat, fmt.Errorf("layer %d: compress: %w", layer, err)
		}
		stat.Packed += n
		if !ok {
			stat.Overhead += n
			continue
		}
		e.Packed = n
		out = append(out, e)
	}
	n, err := m.finish()
	if err != nil {
		return nil, stat, fmt.Errorf("layer %d: compress: %w", layer, err)
	}
	stat.Packed += n
	stat.Overhead += n
	return out, stat, nil
}

// readMember turns one tar header into an entry and reads a file body. ok is false for members no entry records, such as directories.
func readMember(tr io.Reader, h *tar.Header, layer int) (Entry, bool, error) {
	p := path.Clean(strings.TrimPrefix(h.Name, "./"))
	dir, base := path.Split(p)
	switch {
	case base == ".wh..wh..opq":
		return Entry{Layer: layer, Kind: 'o', Path: path.Clean(dir)}, true, nil
	case strings.HasPrefix(base, ".wh."):
		return Entry{Layer: layer, Kind: 'w', Path: path.Join(dir, strings.TrimPrefix(base, ".wh."))}, true, nil
	case h.Typeflag == tar.TypeSymlink:
		return Entry{Layer: layer, Kind: 'l', Path: p, Link: h.Linkname}, true, nil
	case h.Typeflag == tar.TypeLink:
		return Entry{Layer: layer, Kind: 'h', Path: p, Link: path.Clean(strings.TrimPrefix(h.Linkname, "./"))}, true, nil
	case h.Typeflag == tar.TypeReg:
		hs := sha256.New()
		if _, err := io.Copy(hs, tr); err != nil {
			return Entry{}, false, fmt.Errorf("layer %d: read %s: %w", layer, p, err)
		}
		return Entry{Layer: layer, Kind: 'f', Path: p, Size: h.Size, Hash: hex.EncodeToString(hs.Sum(nil))[:20]}, true, nil
	}
	return Entry{}, false, nil
}

// entriesHeader opens every entries file. Files without it predate stream measurement, and their sizes mean something else.
const entriesHeader = "# imgscan entries v2"

func writeEntries(w io.Writer, es []Entry, stats []LayerStat) error {
	if _, err := fmt.Fprintln(w, entriesHeader); err != nil {
		return err
	}
	for _, s := range stats {
		if _, err := fmt.Fprintf(w, "#layer\t%d\t%s\t%d\t%d\t%d\n", s.Layer, s.Codec, s.Level, s.Packed, s.Overhead); err != nil {
			return err
		}
	}
	for _, e := range es {
		if _, err := fmt.Fprintf(w, "%d\t%c\t%d\t%d\t%s\t%s\t%s\n", e.Layer, e.Kind, e.Size, e.Packed, e.Hash, e.Path, e.Link); err != nil {
			return err
		}
	}
	return nil
}

func readEntries(r io.Reader) ([]Entry, []LayerStat, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if lines[0] != entriesHeader {
		return nil, nil, fmt.Errorf("the entries file is from an older imgscan that measured files one at a time; delete it and scan again")
	}
	var out []Entry
	var stats []LayerStat
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "#layer\t"); ok {
			var s LayerStat
			if _, err := fmt.Sscanf(strings.ReplaceAll(rest, "\t", " "), "%d %s %d %d %d", &s.Layer, &s.Codec, &s.Level, &s.Packed, &s.Overhead); err != nil {
				return nil, nil, fmt.Errorf("bad layer line %q: %w", line, err)
			}
			stats = append(stats, s)
			continue
		}
		f := strings.SplitN(line, "\t", 7)
		if len(f) != 7 || len(f[1]) != 1 {
			return nil, nil, fmt.Errorf("bad entry line %q", line)
		}
		var e Entry
		if _, err := fmt.Sscanf(f[0]+" "+f[2]+" "+f[3], "%d %d %d", &e.Layer, &e.Size, &e.Packed); err != nil {
			return nil, nil, fmt.Errorf("bad entry line %q: %w", line, err)
		}
		e.Kind, e.Hash, e.Path, e.Link = f[1][0], f[4], f[5], f[6]
		out = append(out, e)
	}
	return out, stats, nil
}
