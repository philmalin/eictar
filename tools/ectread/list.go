package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/philmalin/eictar/tools/ectread/ect"
)

// entry is the line of -t for one member. A path, a link target or the path
// of a hardlink target that is not UTF-8 has its bytes in a _base64 field
// too.
type entry struct {
	Path           string            `json:"path"`
	PathBase64     string            `json:"path_base64,omitempty"`
	Type           string            `json:"type"`
	Mode           uint64            `json:"mode"`
	UID            *uint64           `json:"uid,omitempty"`
	GID            *uint64           `json:"gid,omitempty"`
	Uname          *string           `json:"uname,omitempty"`
	Gname          *string           `json:"gname,omitempty"`
	Mtime          int64             `json:"mtime"`
	Atime          *int64            `json:"atime,omitempty"`
	Ctime          *int64            `json:"ctime,omitempty"`
	Size           uint64            `json:"size"`
	Link           *string           `json:"link,omitempty"`
	LinkBase64     string            `json:"link_base64,omitempty"`
	Hardlink       *string           `json:"hardlink,omitempty"`
	HardlinkBase64 string            `json:"hardlink_base64,omitempty"`
	Rdev           *[2]uint64        `json:"rdev,omitempty"`
	Xattrs         map[string][]byte `json:"xattrs,omitempty"`
	Sparse         [][2]uint64       `json:"sparse,omitempty"`
	SHA256         string            `json:"sha256,omitempty"`
}

func b64IfNotUTF8(s string) string {
	if utf8.ValidString(s) {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func listArchive(a *ect.Archive, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, m := range a.Live() {
		e := entry{
			Path: m.Path, PathBase64: b64IfNotUTF8(m.Path),
			Type: m.Type, Mode: m.Mode,
			Uname: m.Uname, Gname: m.Gname,
			Mtime: m.Mtime, Atime: m.Atime, Ctime: m.Ctime,
			Size: m.Size, Rdev: m.Rdev, Xattrs: m.Xattrs,
		}
		if m.HasOwner {
			e.UID, e.GID = &m.UID, &m.GID
		}
		switch m.Type {
		case "symlink":
			e.Link, e.LinkBase64 = &m.Link, b64IfNotUTF8(m.Link)
		case "hardlink":
			t := a.ByID(m.Hardlink).Path
			e.Hardlink, e.HardlinkBase64 = &t, b64IfNotUTF8(t)
		}
		for _, s := range m.Sparse {
			e.Sparse = append(e.Sparse, [2]uint64{s.Off, s.Len})
		}
		if m.Type == "reg" || m.Type == "hardlink" {
			h := sha256.New()
			if err := a.Content(m, h); err != nil {
				return fmt.Errorf("%q: %w", m.Path, err)
			}
			e.SHA256 = hex.EncodeToString(h.Sum(nil))
		}
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}
