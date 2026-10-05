package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

func init() { rootCmd.AddCommand(newRepackCmd()) }

func newRepackCmd() *cobra.Command {
	var (
		registry, tokenURL, arch, codec, tmp string
		level, window                        int
		theoretical                          bool
	)
	cmd := &cobra.Command{
		Use:   "repack REPO[:TAG|@DIGEST]",
		Short: "Measure how much smaller each layer gets with its tar reordered by content type",
		Long: "repack writes each layer's members again in three orders and compresses each as one stream:\n" +
			"path order (as BuildKit writes it), grouped by content type, and grouped with identical files as hardlinks.\n" +
			"It holds one layer's file bodies at a time in a temporary file.",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			repo, ref := splitRef(args[0])
			o := ScanOptions{Codec: Codec(codec), Level: level}
			if theoretical {
				o.Codec, o.Window = Zstd, window
				if o.Level == 0 {
					o.Level = 19
				}
			}
			if o.Codec != "" && o.Codec != Zstd && o.Codec != Gzip {
				return fmt.Errorf("--codec %q: want zstd or gzip", codec)
			}
			reg, m, labels, err := openImage(registry, tokenURL, repo, ref, arch)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "# %s:%s linux/%s: each layer's members written again and compressed as one stream\n", repo, ref, arch)
			if theoretical {
				fmt.Fprintf(out, "# typed order, identical files as hardlinks, zstd level %d, %d MB window\n", o.Level, o.Window>>20)
				fmt.Fprintf(out, "%8s %8s %7s  %s\n", "blob MB", "best MB", "diff", "layer")
			} else {
				fmt.Fprintf(out, "%8s %8s %8s %8s  %s\n", "blob MB", "path MB", "typed MB", "+links", "layer")
			}
			var blob int64
			var total RepackStat
			for i, d := range m.Layers {
				body, err := reg.open("blobs/" + d.Digest)
				if err != nil {
					return err
				}
				s, err := repackLayer(body, i, o, tmp, theoretical)
				body.Close()
				if err != nil {
					return err
				}
				blob += d.Size
				total.add(s)
				if theoretical {
					fmt.Fprintf(out, "%8d %8d %7s  %s\n", mb(d.Size), mb(s.Linked), pct(s.Linked, d.Size), label(labels, i))
				} else {
					fmt.Fprintf(out, "%8d %8d %8d %8d  %s\n", mb(d.Size), mb(s.Path), mb(s.Typed), mb(s.Linked), label(labels, i))
				}
			}
			if theoretical {
				fmt.Fprintf(out, "%8d %8d %7s  TOTAL\n", mb(blob), mb(total.Linked), pct(total.Linked, blob))
				return nil
			}
			fmt.Fprintf(out, "%8d %8d %8d %8d  TOTAL\n", mb(blob), mb(total.Path), mb(total.Typed), mb(total.Linked))
			fmt.Fprintf(out, "# typed vs path: %s; typed with links vs path: %s\n", pct(total.Typed, total.Path), pct(total.Linked, total.Path))
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&registry, "registry", "https://ghcr.io", "registry base URL")
	f.StringVar(&tokenURL, "token-url", "", "anonymous token endpoint (default REGISTRY/token?scope=repository:REPO:pull)")
	f.StringVar(&arch, "arch", "amd64", "architecture to pick from a multi-arch index")
	f.StringVar(&codec, "codec", "", "codec for the rewritten streams: zstd or gzip (default: the blob's own codec)")
	f.IntVar(&level, "level", 0, "compression level for --codec (default: the codec's default)")
	f.StringVar(&tmp, "tmp", "", "directory for the per-layer body file (default: the system temp directory)")
	f.BoolVar(&theoretical, "theoretical", false, "compress only the best order (typed, identical files as hardlinks) with zstd and a large window")
	f.IntVar(&window, "window", 512<<20, "zstd window in bytes for --theoretical; a power of two, at most 512 MB")
	return cmd
}

// RepackStat is one layer compressed in member orders.
type RepackStat struct{ Path, Typed, Linked int64 }

func (s *RepackStat) add(o RepackStat) {
	s.Path += o.Path
	s.Typed += o.Typed
	s.Linked += o.Linked
}

type repackMember struct {
	hdr  tar.Header
	off  int64
	hash [32]byte
	head []byte
}

// repackLayer reads one layer, keeps its file bodies in a temporary file, and compresses the members in orders.
// theoretical compresses only the typed order with links.
func repackLayer(r io.Reader, layer int, o ScanOptions, tmp string, theoretical bool) (RepackStat, error) {
	plain, codec, err := decompress(r, layer)
	if err != nil {
		return RepackStat{}, err
	}
	if o.Codec != "" {
		codec = o.Codec
	}
	f, err := os.CreateTemp(tmp, "imgscan-repack-*")
	if err != nil {
		return RepackStat{}, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	ms, err := readMembers(tar.NewReader(plain), f, layer)
	if err != nil {
		return RepackStat{}, err
	}
	if theoretical {
		n, err := compressMembers(typedOrder(ms), f, codec, o, true)
		if err != nil {
			return RepackStat{}, fmt.Errorf("layer %d: %w", layer, err)
		}
		return RepackStat{Linked: n}, nil
	}
	orders := [][]repackMember{ms, typedOrder(ms), typedOrder(ms)}
	sizes := make([]int64, len(orders))
	errs := make([]error, len(orders))
	var wg sync.WaitGroup
	for i := range orders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sizes[i], errs[i] = compressMembers(orders[i], f, codec, o, i == 2)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return RepackStat{}, fmt.Errorf("layer %d: %w", layer, err)
		}
	}
	return RepackStat{Path: sizes[0], Typed: sizes[1], Linked: sizes[2]}, nil
}

// readMembers copies every regular file body to f and records where it starts, its hash and its first bytes.
func readMembers(tr *tar.Reader, f *os.File, layer int) ([]repackMember, error) {
	w := bufio.NewWriterSize(f, 1<<20)
	var off int64
	var ms []repackMember
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("layer %d: tar: %w", layer, err)
		}
		m := repackMember{hdr: *h, off: off}
		if h.Typeflag == tar.TypeReg && h.Size > 0 {
			hs := sha256.New()
			var head bytes.Buffer
			n, err := io.Copy(io.MultiWriter(w, hs, &limitBuffer{&head, 8}), tr)
			if err != nil {
				return nil, fmt.Errorf("layer %d: read %s: %w", layer, h.Name, err)
			}
			off += n
			copy(m.hash[:], hs.Sum(nil))
			m.head = head.Bytes()
		}
		ms = append(ms, m)
	}
	return ms, w.Flush()
}

type limitBuffer struct {
	b *bytes.Buffer
	n int
}

func (l *limitBuffer) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		l.b.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// typedOrder puts directories and opaque markers first, then file bodies grouped by content type, then links and
// whiteouts. Every hardlink then follows the file it names, which an extractor needs.
func typedOrder(ms []repackMember) []repackMember {
	var first, files, rest []repackMember
	for _, m := range ms {
		base := path.Base(m.hdr.Name)
		switch {
		case m.hdr.Typeflag == tar.TypeDir || base == ".wh..wh..opq":
			first = append(first, m)
		case m.hdr.Typeflag == tar.TypeReg && m.hdr.Size > 0 && !strings.HasPrefix(base, ".wh."):
			files = append(files, m)
		default:
			rest = append(rest, m)
		}
	}
	sort.SliceStable(files, func(i, j int) bool {
		ki, kj := contentKey(files[i]), contentKey(files[j])
		if ki != kj {
			return ki < kj
		}
		return files[i].hdr.Size < files[j].hdr.Size
	})
	return append(append(first, files...), rest...)
}

// contentKey groups files by their magic bytes, then by extension.
func contentKey(m repackMember) string {
	magic := "other"
	switch {
	case bytes.HasPrefix(m.head, []byte("\x7fELF")):
		magic = "elf"
	case bytes.HasPrefix(m.head, []byte("PK\x03\x04")):
		magic = "zip"
	case bytes.HasPrefix(m.head, []byte("\x1f\x8b")):
		magic = "gzip"
	case bytes.HasPrefix(m.head, []byte("\x89PNG")):
		magic = "png"
	case bytes.HasPrefix(m.head, []byte("!<arch>")):
		magic = "ar"
	}
	return magic + "\x00" + strings.ToLower(path.Ext(m.hdr.Name))
}

// compressMembers writes ms as a tar stream into codec and returns the compressed size.
// With links, a later file identical to an earlier one becomes a hardlink to it.
func compressMembers(ms []repackMember, bodies io.ReaderAt, codec Codec, o ScanOptions, links bool) (int64, error) {
	m, err := newMeter(codec, o.Level, o.Window)
	if err != nil {
		return 0, err
	}
	if err := writeMembers(m, ms, bodies, links); err != nil {
		return 0, err
	}
	return m.finish()
}

func writeMembers(w io.Writer, ms []repackMember, bodies io.ReaderAt, links bool) error {
	tw := tar.NewWriter(w)
	firstOf := map[[32]byte]string{}
	for _, mem := range ms {
		h := mem.hdr
		body := h.Typeflag == tar.TypeReg && h.Size > 0
		if body && links {
			if name, ok := firstOf[mem.hash]; ok {
				// The source format may not fit the new link name, so the writer picks one.
				h.Typeflag, h.Linkname, h.Size, h.Format = tar.TypeLink, name, 0, tar.FormatUnknown
				body = false
			} else {
				firstOf[mem.hash] = h.Name
			}
		}
		if err := tw.WriteHeader(&h); err != nil {
			return err
		}
		if body {
			if _, err := io.Copy(tw, io.NewSectionReader(bodies, mem.off, h.Size)); err != nil {
				return err
			}
		}
	}
	return tw.Close()
}
