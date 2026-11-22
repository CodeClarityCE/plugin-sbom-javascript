package parser_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeClarityCE/plugin-sbom-javascript/src/parser"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/types"
	packageManager "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js/packageManager"
	"github.com/CodeClarityCE/plugin-sbom-javascript/src/workspace"
)

// Fixtures above this size slow the fuzzer down too much to be useful seeds.
const maxSeedSize = 4 << 10

// addFixtureSeeds adds every small lockfile fixture matching the glob as a seed.
func addFixtureSeeds(f *testing.F, glob string) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "tests", "*", glob))
	if err != nil {
		f.Fatal(err)
	}
	seeds := 0
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		if len(data) <= maxSeedSize {
			f.Add(data)
			seeds++
		}
	}
	if seeds == 0 {
		f.Fatalf("no seed fixtures match %s", glob)
	}
}

// fuzzLockFile checks that parsing any lockfile, then building its workspace, never panics.
func fuzzLockFile(f *testing.F, manager packageManager.PACKAGE_MANAGER, glob string) {
	addFixtureSeeds(f, glob)
	lockFile := filepath.Join(f.TempDir(), "lockfile")
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(lockFile, data, 0o600); err != nil {
			t.Fatal(err)
		}
		project := types.ProjectInformation{LockFile: lockFile, PackageManager: manager}
		info, err := parser.ParseLockFile(project)
		if err != nil {
			return
		}
		workspace.Build(info, project)
	})
}

func FuzzParseNPMLockFile(f *testing.F) {
	fuzzLockFile(f, packageManager.NPM, "package-lock.json.fixture")
}

func FuzzParseYarnLockFile(f *testing.F) {
	fuzzLockFile(f, packageManager.YARN, "yarn.lock.fixture")
}

func FuzzParsePNPMLockFile(f *testing.F) {
	fuzzLockFile(f, packageManager.PNPM, "pnpm-lock.yaml.fixture")
}
