# imgscan

Finds what makes a container image big. It streams every layer straight from the registry. As a result, it never needs disk space for the image, and reports:

- **Dead bytes**: files a layer ships that a later layer overwrites or deletes. They cost pull time and do nothing.
- **Duplicate files**: identical content under different paths, split into duplicates inside one layer (fix with a hardlink) and across layers (fix with a symlink).
- **What remains**: the final filesystem by category and by Python package, in compressed and raw bytes.

```sh
imgscan wow-look-at-my/sglang:dev
imgscan library/ubuntu:24.04 --registry https://registry-1.docker.io \
  --token-url 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/ubuntu:pull'
```

`--entries scan.tsv` saves the per-file hashes after the first scan, so later runs with different rules skip the download. `--rules` regroups the remaining files and `--drop` subtracts the files a planned change deletes. Both take `name<TAB>regex` lines. `examples/sglang-dev.drop` is the drop list of a real cleanup.

Only anonymous pulls are supported. Sizes in the tables are each file deflated alone, so they sum close to, but not exactly to, the registry's layer sizes.

MIT licensed. Install: `go install github.com/wow-look-at-my/imgscan@latest`.
