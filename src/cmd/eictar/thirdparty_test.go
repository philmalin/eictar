package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestThirdPartyListsEveryModule: THIRD_PARTY.md names each module of go.mod
// at the version that go.mod requires. A release ships that file because the
// licenses of the modules require their texts with the binary, so a module
// that is added or updated without it is caught here.
func TestThirdPartyListsEveryModule(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	gomod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	notices, err := os.ReadFile(filepath.Join(root, "THIRD_PARTY.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(notices)

	inRequire := false
	found := 0
	for _, line := range strings.Split(string(gomod), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "require (":
			inRequire = true
			continue
		case line == ")":
			inRequire = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimPrefix(line, "require ")
		case !inRequire:
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		path, version := fields[0], fields[1]
		found++
		if !strings.Contains(text, "### "+path+" "+version+"\n") {
			t.Errorf("THIRD_PARTY.md has no license text for %s %s", path, version)
		}
		if !strings.Contains(text, "| "+version+" |") || !strings.Contains(text, "`"+path+"`") {
			t.Errorf("THIRD_PARTY.md has no table row for %s %s", path, version)
		}
	}
	if found == 0 {
		t.Fatal("found no modules in go.mod")
	}
}
