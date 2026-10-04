package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
)

// scanAll streams every layer of m, jobs at a time, and returns all entries.
func scanAll(r *Registry, m manifest, jobs int, progress io.Writer) ([]Entry, error) {
	var (
		mu   sync.Mutex
		all  []Entry
		errs []string
		wg   sync.WaitGroup
	)
	sem := make(chan struct{}, max(jobs, 1))
	for i, d := range m.Layers {
		wg.Add(1)
		go func(i int, d descriptor) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			es, err := scanBlob(r, d.Digest, i)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err.Error())
				return
			}
			all = append(all, es...)
			fmt.Fprintf(progress, "layer %d: %d entries\n", i, len(es))
		}(i, d)
	}
	wg.Wait()
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return all, nil
}

func scanBlob(r *Registry, digest string, layer int) ([]Entry, error) {
	body, err := r.open("blobs/" + digest)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return scanLayer(body, layer)
}

// loadOrScan reads the entries file when it exists. Otherwise it scans and, when a path is given, writes the file.
func loadOrScan(r *Registry, m manifest, cache string, jobs int, progress io.Writer) ([]Entry, error) {
	if cache != "" {
		if f, err := os.Open(cache); err == nil {
			defer f.Close()
			return readEntries(f)
		}
	}
	es, err := scanAll(r, m, jobs, progress)
	if err != nil || cache == "" {
		return es, err
	}
	f, err := os.Create(cache)
	if err != nil {
		return nil, err
	}
	if err := writeEntries(f, es); err != nil {
		f.Close()
		return nil, err
	}
	return es, f.Close()
}
