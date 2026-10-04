package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = newRootCmd()

func newRootCmd() *cobra.Command {
	var (
		registry, tokenURL, arch, cache, rulesFile, dropFile string
		jobs, top                                            int
	)
	cmd := &cobra.Command{
		Use:   "imgscan REPO[:TAG|@DIGEST]",
		Short: "Find dead bytes, duplicate files and the size breakdown of a registry image",
		Long: "imgscan streams every layer of an image from its registry without storing it.\n" +
			"It hashes each file and measures its gzip size, then reports bytes that later layers hide,\n" +
			"identical files, and what the final filesystem is made of.",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			repo, ref := splitRef(args[0])
			if tokenURL == "" {
				tokenURL = fmt.Sprintf("%s/token?scope=repository:%s:pull", registry, repo)
			}
			o := Options{Top: top}
			var err error
			if o.Rules, err = rulesFrom(rulesFile); err != nil {
				return err
			}
			if o.Drop, err = rulesFrom(dropFile); err != nil {
				return err
			}
			client := &http.Client{}
			tok, err := anonToken(client, tokenURL)
			if err != nil {
				return err
			}
			reg := &Registry{Base: registry, Repo: repo, Token: tok, HTTP: client}
			m, labels, err := reg.Image(ref, arch)
			if err != nil {
				return err
			}
			o.Labels = labels
			es, err := loadOrScan(reg, m, cache, jobs, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			var gz int64
			for _, l := range m.Layers {
				gz += l.Size
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "# %s:%s linux/%s: %d layers, %d MB compressed in the registry\n", repo, ref, arch, len(m.Layers), mb(gz))
			fmt.Fprintf(out, "# gz MB below is each file deflated on its own; it sums near, not to, the registry size.\n")
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
