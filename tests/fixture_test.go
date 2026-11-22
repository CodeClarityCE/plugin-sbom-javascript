package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureSuffix keeps GitHub from reading fixture manifests as real dependencies.
const fixtureSuffix = ".fixture"

// realManifestNames are the files GitHub's dependency graph picks up.
var realManifestNames = map[string]bool{
	"package.json":        true,
	"package-lock.json":   true,
	"npm-shrinkwrap.json": true,
	"yarn.lock":           true,
	"pnpm-lock.yaml":      true,
}

// sourceDir is this tests folder, where the fixtures and goldens live.
var sourceDir = func() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return dir
}()

// restoreFixture copies tests/<name> into a tempdir under the same name with the
// .fixture suffix removed, moves the test there and returns "./<name>" for plugin.Start.
func restoreFixture(t *testing.T, name string) string {
	t.Helper()
	tmp := t.TempDir()
	src := os.DirFS(filepath.Join(sourceDir, name))
	err := fs.WalkDir(src, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dst := filepath.Join(tmp, name, strings.TrimSuffix(filepath.FromSlash(path), fixtureSuffix))
		if d.IsDir() {
			return os.MkdirAll(dst, 0o750)
		}
		data, err := fs.ReadFile(src, path)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(tmp)
	return "./" + name
}

// TestFixturesHaveNoRealManifestNames fails on any fixture file GitHub would scan.
func TestFixturesHaveNoRealManifestNames(t *testing.T) {
	err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && realManifestNames[d.Name()] {
			rel, _ := filepath.Rel(sourceDir, path)
			t.Errorf("tests/%s: rename it to %s%s", rel, d.Name(), fixtureSuffix)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
