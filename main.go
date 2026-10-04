// Command imgscan reports dead bytes, duplicate files and the size breakdown of a registry image.
package main

import "os"

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
