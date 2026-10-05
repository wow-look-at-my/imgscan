package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = newRootCmd()

func newRootCmd() *cobra.Command {
	var (
		registry, tokenURL, arch, cache, rulesFile, dropFile, codec string
		jobs, top, level                                            int
	)
	cmd := &cobra.Command{
		Use:   "imgscan REPO[:TAG|@DIGEST]",
		Short: "Find dead bytes, duplicate files and the size breakdown of a registry image",
		Long: "imgscan streams every layer of an image from its registry without storing it.\n" +
			"It hashes each file and compresses each layer's tar stream again as one stream, as the registry blob is,\n" +
			"so each file's packed size is its share of that stream. It then reports bytes that later layers hide,\n" +
			"identical files, and what the final filesystem is made of.",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			repo, ref := splitRef(args[0])
			o := Options{Top: top}
			var err error
			if o.Rules, err = rulesFrom(rulesFile); err != nil {
				return err
			}
			if o.Drop, err = rulesFrom(dropFile); err != nil {
				return err
			}
			reg, m, labels, err := openImage(registry, tokenURL, repo, ref, arch)
			if err != nil {
				return err
			}
			o.Labels = labels
			so := ScanOptions{Codec: Codec(codec), Level: level}
			if codec != "" && so.Codec != Zstd && so.Codec != Gzip {
				return fmt.Errorf("--codec %q: want zstd or gzip", codec)
			}
			es, stats, err := loadOrScan(reg, m, cache, jobs, so, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			var blob int64
			for _, l := range m.Layers {
				blob += l.Size
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "# %s:%s linux/%s: %d layers, %d MB compressed in the registry\n", repo, ref, arch, len(m.Layers), mb(blob))
			fmt.Fprintf(out, "# pack MB is each file's share of its layer's tar stream compressed again; the layer table shows how close that lands to the registry.\n")
			reportLayers(out, m.Layers, stats, labels)
			report(out, es, o)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&registry, "registry", "https://ghcr.io", "registry base URL")
	f.StringVar(&tokenURL, "token-url", "", "anonymous token endpoint (default REGISTRY/token?scope=repository:REPO:pull)")
	f.StringVar(&arch, "arch", "amd64", "architecture to pick from a multi-arch index")
	f.StringVar(&cache, "entries", "", "entries file: read when it exists, otherwise written after the scan")
	f.StringVar(&rulesFile, "rules", "", "file of name<TAB>regex lines that group the remaining files (first match wins)")
	f.StringVar(&dropFile, "drop", "", "file of name<TAB>regex lines for files a planned change deletes")
	f.StringVar(&codec, "codec", "", "codec to compress each layer stream again with: zstd or gzip (default: the blob's own codec)")
	f.IntVar(&level, "level", 0, "compression level for --codec, in zstd or gzip numbers (default: the codec's default)")
	f.IntVarP(&jobs, "jobs", "j", 4, "layers scanned at once")
	f.IntVar(&top, "top", 30, "rows shown in the long tables")
	return cmd
}

// splitRef splits "repo:tag" or "repo@digest". A bare repo means the tag latest.
func splitRef(s string) (repo, ref string) {
	if i := strings.Index(s, "@"); i >= 0 {
		return s[:i], s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		return s[:i], s[i+1:]
	}
	return s, "latest"
}

func rulesFrom(file string) ([]Rule, error) {
	if file == "" {
		return nil, nil
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseRules(f)
}
