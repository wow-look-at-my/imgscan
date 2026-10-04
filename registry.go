package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Registry reads one repository of an OCI registry with an anonymous pull token.
type Registry struct {
	Base  string
	Repo  string
	Token string
	HTTP  *http.Client
}

const accept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

func (r *Registry) get(p string, out any) error {
	body, err := r.open(p)
	if err != nil {
		return err
	}
	defer body.Close()
	return json.NewDecoder(body).Decode(out)
}

func (r *Registry) open(p string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", r.Base+"/v2/"+r.Repo+"/"+p, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	if r.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Token)
	}
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", p, resp.Status)
	}
	return resp.Body, nil
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	} `json:"platform"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"`
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
}

type imageConfig struct {
	History []struct {
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
}

// Image resolves ref (a tag or digest) to its arch manifest and one label per layer.
func (r *Registry) Image(ref, arch string) (manifest, []string, error) {
	var m manifest
	if err := r.get("manifests/"+ref, &m); err != nil {
		return m, nil, err
	}
	if len(m.Manifests) > 0 {
		digest := ""
		for _, d := range m.Manifests {
			if d.Platform != nil && d.Platform.OS == "linux" && d.Platform.Architecture == arch {
				digest = d.Digest
				break
			}
		}
		if digest == "" {
			return m, nil, fmt.Errorf("%s has no linux/%s manifest", ref, arch)
		}
		m = manifest{}
		if err := r.get("manifests/"+digest, &m); err != nil {
			return m, nil, err
		}
	}
	var c imageConfig
	if err := r.get("blobs/"+m.Config.Digest, &c); err != nil {
		return m, nil, err
	}
	var labels []string
	for _, h := range c.History {
		if !h.EmptyLayer {
			labels = append(labels, shortCmd(h.CreatedBy))
		}
	}
	return m, labels, nil
}

var argPrefix = regexp.MustCompile(`^RUN \|[0-9]+ (\S+=\S* )*`)

// shortCmd turns a history created_by into a one-line label: build args and the shell prefix removed.
func shortCmd(s string) string {
	s = argPrefix.ReplaceAllString(s, "RUN ")
	s = strings.ReplaceAll(strings.ReplaceAll(s, "/bin/sh -c ", ""), "#(nop) ", "")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 90 {
		s = s[:90]
	}
	return s
}

// anonToken asks a registry token endpoint (the ghcr.io and Docker Hub form) for an anonymous pull token.
func anonToken(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token: %s", resp.Status)
	}
	var t struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return "", err
	}
	return t.Token, nil
}
