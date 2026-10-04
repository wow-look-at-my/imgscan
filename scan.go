package main

import (
	"archive/tar"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"
)

// Entry is one tar member of one layer. Kind is f (file), l (symlink), h (hardlink), w (whiteout), o (opaque dir).
type Entry struct {
	Layer int
	Kind  byte
	Path  string
	Size  int64
	Gz    int64
	Hash  string
	Link  string
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// scanLayer reads one gzip layer and returns its entries with content hashes and per-file gzip sizes.
func scanLayer(r io.Reader, layer int) ([]Entry, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("layer %d: gzip: %w", layer, err)
	}
	tr := tar.NewReader(gz)
	var out []Entry
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("layer %d: tar: %w", layer, err)
		}
		p := path.Clean(strings.TrimPrefix(h.Name, "./"))
		dir, base := path.Split(p)
		switch {
		case base == ".wh..wh..opq":
			out = append(out, Entry{Layer: layer, Kind: 'o', Path: path.Clean(dir)})
		case strings.HasPrefix(base, ".wh."):
			out = append(out, Entry{Layer: layer, Kind: 'w', Path: path.Join(dir, strings.TrimPrefix(base, ".wh."))})
		case h.Typeflag == tar.TypeSymlink:
			out = append(out, Entry{Layer: layer, Kind: 'l', Path: p, Link: h.Linkname})
		case h.Typeflag == tar.TypeLink:
			out = append(out, Entry{Layer: layer, Kind: 'h', Path: p, Link: path.Clean(strings.TrimPrefix(h.Linkname, "./"))})
		case h.Typeflag == tar.TypeReg:
			e, err := hashFile(tr, layer, p, h.Size)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		}
	}
}

// hashFile reads one file body.
func hashFile(r io.Reader, layer int, p string, size int64) (Entry, error) {
	hs := sha256.New()
	cw := &countWriter{}
	fw, err := flate.NewWriter(cw, 6)
	if err != nil {
		return Entry{}, err
	}
	if _, err := io.Copy(io.MultiWriter(hs, fw), r); err != nil {
		return Entry{}, fmt.Errorf("layer %d: read %s: %w", layer, p, err)
	}
	if err := fw.Close(); err != nil {
		return Entry{}, err
	}
	return Entry{Layer: layer, Kind: 'f', Path: p, Size: size, Gz: cw.n, Hash: hex.EncodeToString(hs.Sum(nil))[:20]}, nil
}

func writeEntries(w io.Writer, es []Entry) error {
	for _, e := range es {
		if _, err := fmt.Fprintf(w, "%d\t%c\t%d\t%d\t%s\t%s\t%s\n", e.Layer, e.Kind, e.Size, e.Gz, e.Hash, e.Path, e.Link); err != nil {
			return err
		}
	}
	return nil
}

func readEntries(r io.Reader) ([]Entry, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.SplitN(line, "\t", 7)
		if len(f) != 7 || len(f[1]) != 1 {
			return nil, fmt.Errorf("bad entry line %q", line)
		}
		var e Entry
		if _, err := fmt.Sscanf(f[0]+" "+f[2]+" "+f[3], "%d %d %d", &e.Layer, &e.Size, &e.Gz); err != nil {
			return nil, fmt.Errorf("bad entry line %q: %w", line, err)
		}
		e.Kind, e.Hash, e.Path, e.Link = f[1][0], f[4], f[5], f[6]
		out = append(out, e)
	}
	return out, nil
}
