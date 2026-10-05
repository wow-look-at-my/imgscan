package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
)

// scanAll streams every layer of m, jobs at a time, and returns all entries and one stat per layer.
func scanAll(r *Registry, m manifest, jobs int, o ScanOptions, progress io.Writer) ([]Entry, []LayerStat, error) {
	var (
		mu    sync.Mutex
		all   []Entry
		stats = make([]LayerStat, len(m.Layers))
		errs  []string
		wg    sync.WaitGroup
	)
	sem := make(chan struct{}, max(jobs, 1))
	for i, d := range m.Layers {
		wg.Add(1)
		go func(i int, d descriptor) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			es, st, err := scanBlob(r, d.Digest, i, o)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err.Error())
				return
			}
			all = append(all, es...)
			stats[i] = st
			fmt.Fprintf(progress, "layer %d: %d entries\n", i, len(es))
		}(i, d)
	}
	wg.Wait()
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return all, stats, nil
}

func scanBlob(r *Registry, digest string, layer int, o ScanOptions) ([]Entry, LayerStat, error) {
	body, err := r.open("blobs/" + digest)
	if err != nil {
		return nil, LayerStat{}, err
	}
	defer body.Close()
	return scanLayer(body, layer, o)
}

// loadOrScan reads the entries file when it exists. Otherwise it scans and, when a path is given, writes the file.
// A file measured with a different codec or level than o asks for is an error, not a silent mix.
func loadOrScan(r *Registry, m manifest, cache string, jobs int, o ScanOptions, progress io.Writer) ([]Entry, []LayerStat, error) {
	if cache != "" {
		if f, err := os.Open(cache); err == nil {
			defer f.Close()
			es, stats, err := readEntries(f)
			if err != nil {
				return nil, nil, err
			}
			for _, s := range stats {
				if (o.Codec != "" && s.Codec != o.Codec) || s.Level != o.Level {
					return nil, nil, fmt.Errorf("%s measured layer %d with %s level %d; delete it or pass the same --codec and --level", cache, s.Layer, s.Codec, s.Level)
				}
			}
			return es, stats, nil
		}
	}
	es, stats, err := scanAll(r, m, jobs, o, progress)
	if err != nil || cache == "" {
		return es, stats, err
	}
	f, err := os.Create(cache)
	if err != nil {
		return nil, nil, err
	}
	if err := writeEntries(f, es, stats); err != nil {
		f.Close()
		return nil, nil, err
	}
	return es, stats, f.Close()
}
