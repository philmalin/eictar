// Package compare checks that eictar and the second reader (package ect)
// agree on an archive (doc/design.md 13.5, step 2): the listing of
// eictar -t --json against the index that the reader decoded, and a tree
// that eictar extracted against the content that the reader decodes. It
// runs nothing: the caller gives what eictar wrote.
package compare

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/philmalin/eictar/tools/ectread/ect"
)

// jsonMember is an entry of eictar -t --json (doc/design.md 10.9). A field
// that this type does not know fails the comparison, so that a new field is
// compared too.
type jsonMember struct {
	Path       string   `json:"path"`
	PathBase64 string   `json:"path_base64"`
	Type       string   `json:"type"`
	Size       uint64   `json:"size"`
	Mode       uint64   `json:"mode"`
	MTime      string   `json:"mtime"`
	Target     *string  `json:"target"`
	LinkTo     *string  `json:"hardlink_to"`
	SameAs     *string  `json:"same_as"`
	SameAsDead bool     `json:"same_as_deleted"`
	UID        *uint64  `json:"uid"`
	GID        *uint64  `json:"gid"`
	Uname      string   `json:"uname"`
	Gname      string   `json:"gname"`
	RDev       []uint64 `json:"rdev"`
	Sparse     bool     `json:"sparse"`
	Xattrs     []string `json:"xattrs"`
	Codec      *struct {
		Name   string         `json:"name"`
		Params map[string]any `json:"params"`
	} `json:"codec"`
	StoredSize *uint64 `json:"stored_size"`
	Chunks     *int    `json:"chunks"`
	Encrypted  *bool   `json:"encrypted"`
	Digest     string  `json:"digest"`
}

// problems collects the differences, and gives one error for them.
type problems []string

func (p *problems) add(path, format string, a ...any) {
	*p = append(*p, fmt.Sprintf("%q: ", path)+fmt.Sprintf(format, a...))
}

func (p problems) err(what string) error {
	if len(p) == 0 {
		return nil
	}
	sort.Strings(p)
	if len(p) > 20 {
		p = append(p[:20], fmt.Sprintf("and %d more", len(p)-20))
	}
	return fmt.Errorf("%s: eictar and the second reader differ:\n  %s", what, strings.Join(p, "\n  "))
}

// livePaths maps the path of each live member to it. Two live members with
// one path are a difference: eictar lists one entry for each path.
func livePaths(a *ect.Archive, p *problems) map[string]*ect.Member {
	out := map[string]*ect.Member{}
	for _, m := range a.Live() {
		if out[m.Path] != nil {
			p.add(m.Path, "two live members have this path")
		}
		out[m.Path] = m
	}
	return out
}

// Listing compares the output of eictar -t --json with the archive.
func Listing(a *ect.Archive, listing []byte) error {
	dec := json.NewDecoder(bytes.NewReader(listing))
	dec.DisallowUnknownFields()
	var got []jsonMember
	if err := dec.Decode(&got); err != nil {
		return fmt.Errorf("the listing of eictar: %w", err)
	}
	var p problems
	want := livePaths(a, &p)
	seen := map[string]bool{}
	for _, j := range got {
		path := j.Path
		if j.PathBase64 != "" {
			b, err := base64.StdEncoding.DecodeString(j.PathBase64)
			if err != nil {
				p.add(j.Path, "path_base64: %v", err)
				continue
			}
			path = string(b)
		}
		if seen[path] {
			p.add(path, "eictar lists it twice")
		}
		seen[path] = true
		m := want[path]
		if m == nil {
			p.add(path, "eictar lists it, and it is not a live member")
			continue
		}
		member(a, m, j, &p)
	}
	for path := range want {
		if !seen[path] {
			p.add(path, "a live member that eictar does not list")
		}
	}
	return p.err("listing")
}

// member compares one entry of the listing with its member.
func member(a *ect.Archive, m *ect.Member, j jsonMember, p *problems) {
	diff := func(field string, got, want any) {
		p.add(m.Path, "%s: eictar gives %v, the reader %v", field, got, want)
	}
	if (j.PathBase64 != "") == utf8.ValidString(m.Path) {
		diff("path_base64", j.PathBase64 != "", !utf8.ValidString(m.Path))
	}
	if j.Type != m.Type {
		diff("type", j.Type, m.Type)
	}
	if j.Size != m.Size {
		diff("size", j.Size, m.Size)
	}
	if j.Mode != m.Mode {
		diff("mode", j.Mode, m.Mode)
	}
	if t, err := time.Parse(time.RFC3339Nano, j.MTime); err != nil || t.UnixNano() != m.Mtime {
		diff("mtime", j.MTime, time.Unix(0, m.Mtime).UTC().Format(time.RFC3339Nano))
	}
	optText(p, m.Path, "target", j.Target, m.Type == "symlink", m.Link)
	var linkTo, sameAs string
	var sameAsDead bool
	if m.Type == "hardlink" {
		linkTo = a.ByID(m.Hardlink).Path
	}
	if m.Data != 0 {
		o := a.ByID(m.Data)
		sameAs, sameAsDead = o.Path, o.Dead
	}
	optText(p, m.Path, "hardlink_to", j.LinkTo, m.Type == "hardlink", linkTo)
	optText(p, m.Path, "same_as", j.SameAs, m.Data != 0, sameAs)
	if j.SameAsDead != sameAsDead {
		diff("same_as_deleted", j.SameAsDead, sameAsDead)
	}
	if (j.UID != nil) != m.HasOwner || (j.GID != nil) != m.HasOwner ||
		m.HasOwner && (*j.UID != m.UID || *j.GID != m.GID) {
		diff("uid and gid", owner(j.UID, j.GID), owner(&m.UID, &m.GID))
	}
	if j.Uname != deref(m.Uname) {
		diff("uname", j.Uname, deref(m.Uname))
	}
	if j.Gname != deref(m.Gname) {
		diff("gname", j.Gname, deref(m.Gname))
	}
	var rdev []uint64
	if m.Rdev != nil {
		rdev = m.Rdev[:]
	}
	if !slices.Equal(j.RDev, rdev) {
		diff("rdev", j.RDev, rdev)
	}
	if j.Sparse != m.IsSparse {
		diff("sparse", j.Sparse, m.IsSparse)
	}
	var names []string
	for k := range m.Xattrs {
		names = append(names, k)
	}
	sort.Strings(names)
	xs := slices.Clone(j.Xattrs)
	sort.Strings(xs)
	if !slices.Equal(xs, names) {
		diff("xattrs", xs, names)
	}
	content(a, m, j, p, diff)
}

// content compares the fields of the content of a member.
func content(a *ect.Archive, m *ect.Member, j jsonMember, p *problems, diff func(string, any, any)) {
	if m.Type != "reg" {
		if j.Codec != nil || j.StoredSize != nil || j.Chunks != nil || j.Encrypted != nil || j.Digest != "" {
			p.add(m.Path, "eictar gives fields of content on a %s", m.Type)
		}
		return
	}
	if j.Digest != hex.EncodeToString(m.Digest) {
		diff("digest", j.Digest, hex.EncodeToString(m.Digest))
	}
	if m.Data != 0 {
		// A reference: its content is in the blob of its owner.
		if j.Codec != nil || j.Chunks != nil || j.Encrypted != nil || j.StoredSize == nil || *j.StoredSize != 0 {
			p.add(m.Path, "eictar gives a reference fields of a blob of its own")
		}
		return
	}
	o := m
	codec := "none"
	if o.Codec >= 0 {
		codec = a.Codecs[o.Codec].Name
	}
	if j.Codec == nil || j.Codec.Name != codec {
		diff("codec", j.Codec, codec)
	}
	if j.StoredSize == nil || *j.StoredSize != o.Len {
		diff("stored_size", ptr(j.StoredSize), o.Len)
	}
	if j.Chunks == nil || *j.Chunks != len(o.Chunks) {
		diff("chunks", ptr(j.Chunks), len(o.Chunks))
	}
	sealed := a.Encrypted && o.HasBlob
	if j.Encrypted == nil || *j.Encrypted != sealed {
		diff("encrypted", ptr(j.Encrypted), sealed)
	}
}

func optText(p *problems, path, field string, got *string, present bool, want string) {
	switch {
	case (got != nil) != present:
		p.add(path, "%s: eictar gives it: %v, the reader: %v", field, got != nil, present)
	case got != nil && utf8.ValidString(want) && *got != want:
		p.add(path, "%s: eictar gives %q, the reader %q", field, *got, want)
	}
}

func owner(uid, gid *uint64) string {
	if uid == nil || gid == nil {
		return "none"
	}
	return fmt.Sprintf("%d:%d", *uid, *gid)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func ptr[T any](v *T) any {
	if v == nil {
		return "nothing"
	}
	return *v
}

// Tree compares a tree that eictar extracted into root with the archive.
// Each live member is there with its type, and a file has the content
// that the reader decodes. A hardlink is one file with its target, when the
// target is live. Nothing else is there, apart from the directories above a
// member. Modes, times, owners and extended attributes are in the listing,
// and Listing compares them. A device and a socket need root, so they are
// not compared. eictar makes no pipe on Windows and macOS (doc/design.md
// 15.1), so there a pipe is not compared either. Nor are the types in skip.
func Tree(a *ect.Archive, root string, skip ...string) error {
	var p problems
	members := livePaths(a, &p)
	above := map[string]bool{}
	for path := range members {
		for d := path; strings.Contains(d, "/"); {
			d = d[:strings.LastIndex(d, "/")]
			above[d] = true
		}
	}
	for path, m := range members {
		if path == "." || !validPath(path) {
			continue
		}
		abs := filepath.Join(root, filepath.FromSlash(path))
		fi, err := os.Lstat(abs)
		ignore := m.Type == "sock" || m.Type == "chardev" || m.Type == "blockdev" ||
			m.Type == "fifo" && (runtime.GOOS == "windows" || runtime.GOOS == "darwin") || slices.Contains(skip, m.Type)
		if ignore {
			continue
		}
		if err != nil {
			p.add(path, "not extracted: %v", err)
			continue
		}
		file(a, m, abs, fi, root, &p)
	}
	err := filepath.WalkDir(root, func(abs string, d fs.DirEntry, err error) error {
		if err != nil || abs == root {
			return err
		}
		rel, _ := filepath.Rel(root, abs)
		rel = filepath.ToSlash(rel)
		if members[rel] == nil && !(d.IsDir() && above[rel]) {
			p.add(rel, "extracted, and not a live member")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return p.err("extraction")
}

// file compares one extracted path with its member.
func file(a *ect.Archive, m *ect.Member, abs string, fi fs.FileInfo, root string, p *problems) {
	switch m.Type {
	case "dir":
		if !fi.IsDir() {
			p.add(m.Path, "a %v, not a directory", fi.Mode().Type())
		}
	case "symlink":
		if fi.Mode()&fs.ModeSymlink == 0 {
			p.add(m.Path, "a %v, not a symbolic link", fi.Mode().Type())
		} else if t, err := os.Readlink(abs); err != nil || filepath.ToSlash(t) != m.Link {
			p.add(m.Path, "links to %q, the reader gives %q", t, m.Link)
		}
	case "fifo":
		if fi.Mode()&fs.ModeNamedPipe == 0 {
			p.add(m.Path, "a %v, not a pipe", fi.Mode().Type())
		}
	case "reg", "hardlink":
		if !fi.Mode().IsRegular() {
			p.add(m.Path, "a %v, not a file", fi.Mode().Type())
			return
		}
		got, err := hashFile(abs)
		if err != nil {
			p.add(m.Path, "%v", err)
			return
		}
		h := sha256.New()
		if err := a.Content(m, h); err != nil {
			p.add(m.Path, "eictar extracted it, and the reader gives %v", err)
			return
		}
		if !bytes.Equal(got, h.Sum(nil)) {
			p.add(m.Path, "the content differs")
		}
		if m.Type == "hardlink" {
			t := a.ByID(m.Hardlink)
			if t.Dead || !validPath(t.Path) {
				return
			}
			tfi, err := os.Lstat(filepath.Join(root, filepath.FromSlash(t.Path)))
			if err != nil || !os.SameFile(fi, tfi) {
				p.add(m.Path, "not one file with %q", t.Path)
			}
		}
	}
}

func hashFile(abs string) ([]byte, error) {
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// validPath is the rule of doc/format.md 9.1, without the path ".". eictar
// refuses to extract a member whose path breaks it.
func validPath(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") {
		return false
	}
	for _, c := range strings.Split(path, "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}
