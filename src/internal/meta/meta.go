// Package meta reads and restores the metadata an archive keeps beyond file
// content: ownership, special mode bits, extended attributes (and the POSIX
// ACLs stored in them), holes, device numbers, and link times.
//
// Everything here is either a pure conversion or a thin wrapper round one
// system call. The policy - what to record, what to restore, and as whom -
// lives in the archive package (doc/design.md 7 and 14).
package meta

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"sync"
)

// ErrUnsupported means this platform or filesystem cannot do what was asked.
var ErrUnsupported = errors.New("not supported on this platform")

// Capabilities says what the metadata code of a platform does
// (doc/design.md 15.1). The tests read it, so that each one runs where its
// feature exists and says why it does not elsewhere.
type Capabilities struct {
	Metadata bool // owner, special bits, times, hardlinks, link times
	Xattrs   bool // extended attributes
	Holes    bool // sparse files found with SEEK_DATA and stored as holes
	Fifos    bool // named pipes created on extraction
	Devices  bool // device nodes created on extraction (as root)
}

// ErrRefused means the destination does not take one extended attribute: the
// filesystem has none, or the platform has no place for the name, as Linux
// has none for macOS's com.apple.* names. Extraction lists such names in one
// notice (doc/design.md 7.7).
var ErrRefused = errors.New("the destination does not take this extended attribute")

// Info is what the archive needs to know about a filesystem object beyond its
// type and size.
type Info struct {
	Dev, Ino     uint64 // identity, for hardlink detection
	Nlink        uint64
	UID, GID     uint32
	Major, Minor uint32 // device number, for device nodes
	ATimeNanos   int64
	MTimeNanos   int64
	Blocks       int64 // 512-byte blocks allocated, for hole detection
	OK           bool  // false when the platform gave no system information
	// HasID is true when Dev, Ino and Nlink are valid. The UNIX-like
	// platforms give them with OK. Windows gives them without OK: it has an
	// identity for a file, but no owner and no mode.
	HasID bool
}

// The special mode bits as the kernel numbers them. os.FileMode keeps them
// in its own high bits, so they have to be translated both ways.
const (
	bitSetuid = 0o4000
	bitSetgid = 0o2000
	bitSticky = 0o1000
)

// UnixMode returns the permission, setuid, setgid and sticky bits of m, in
// the kernel's numbering. This is what the index stores.
func UnixMode(m fs.FileMode) uint32 {
	bits := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		bits |= bitSetuid
	}
	if m&fs.ModeSetgid != 0 {
		bits |= bitSetgid
	}
	if m&fs.ModeSticky != 0 {
		bits |= bitSticky
	}
	return bits
}

// FileMode is the inverse of UnixMode. With special false it returns the
// permission bits only, which is what extraction applies unless the user asks
// for -p: a setuid bit from an archive is not restored by default.
func FileMode(bits uint32, special bool) fs.FileMode {
	m := fs.FileMode(bits & 0o777)
	if !special {
		return m
	}
	if bits&bitSetuid != 0 {
		m |= fs.ModeSetuid
	}
	if bits&bitSetgid != 0 {
		m |= fs.ModeSetgid
	}
	if bits&bitSticky != 0 {
		m |= fs.ModeSticky
	}
	return m
}

// Names maps between numeric ids and user and group names, with a cache.
//
// Archives record both, and extraction prefers the name, as tar does: uid
// 1000 on one machine is rarely the same person as uid 1000 on another, but
// "alice" usually is. A lookup can read /etc/passwd or ask NSS, so the
// result is cached for the run. It is safe for concurrent use.
type Names struct {
	mu     sync.Mutex
	users  map[uint32]string
	groups map[uint32]string
	uids   map[string]int64 // -1 when the name does not resolve
	gids   map[string]int64
}

// NewNames returns an empty cache.
func NewNames() *Names {
	return &Names{
		users:  map[uint32]string{},
		groups: map[uint32]string{},
		uids:   map[string]int64{},
		gids:   map[string]int64{},
	}
}

// UserName returns the name for uid, or "" if it has none.
func (n *Names) UserName(uid uint32) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if name, ok := n.users[uid]; ok {
		return name
	}
	name := ""
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		name = u.Username
	}
	n.users[uid] = name
	return name
}

// GroupName returns the name for gid, or "" if it has none.
func (n *Names) GroupName(gid uint32) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if name, ok := n.groups[gid]; ok {
		return name
	}
	name := ""
	if g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10)); err == nil {
		name = g.Name
	}
	n.groups[gid] = name
	return name
}

// ResolveUser returns the uid to restore: the local id of name when the name
// exists here, otherwise the recorded id.
func (n *Names) ResolveUser(name string, recorded uint32) uint32 {
	if name == "" {
		return recorded
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	id, ok := n.uids[name]
	if !ok {
		id = -1
		if u, err := user.Lookup(name); err == nil {
			if v, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
				id = int64(v)
			}
		}
		n.uids[name] = id
	}
	if id < 0 {
		return recorded
	}
	return uint32(id)
}

// ResolveGroup is ResolveUser for groups.
func (n *Names) ResolveGroup(name string, recorded uint32) uint32 {
	if name == "" {
		return recorded
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	id, ok := n.gids[name]
	if !ok {
		id = -1
		if g, err := user.LookupGroup(name); err == nil {
			if v, err := strconv.ParseUint(g.Gid, 10, 32); err == nil {
				id = int64(v)
			}
		}
		n.gids[name] = id
	}
	if id < 0 {
		return recorded
	}
	return uint32(id)
}

// IsRoot reports whether the process has the effective uid 0, which chown and
// mknod need.
func IsRoot() bool { return os.Geteuid() == 0 }

// Segment is one run of real data in a sparse file.
type Segment struct {
	Offset int64
	Length int64
}

// XattrClass groups extended attribute names by who may restore them.
//
// Names are recorded exactly as the platform gives them (doc/design.md 7.7):
// user.foo on Linux and the BSDs, com.apple.quarantine on macOS. The class
// decides only which options and which privilege apply to a name. Whether the
// destination takes it is found out when it is set.
type XattrClass int

const (
	// XattrUser is the user.* namespace: any owner may set it.
	XattrUser XattrClass = iota
	// XattrACL is a POSIX ACL, stored as system.posix_acl_access or
	// system.posix_acl_default.
	XattrACL
	// XattrPrivileged is security.*, trusted.* and the rest of system.*,
	// which need privilege to set and are often specific to one machine or
	// filesystem (an SELinux label, the system namespace of FreeBSD).
	XattrPrivileged
	// XattrPlain is a name with no namespace, which is what every name looks
	// like on macOS. It is treated as a user attribute.
	XattrPlain
)

// ClassifyXattr returns the class of an attribute name.
func ClassifyXattr(name string) XattrClass {
	switch {
	case len(name) > 5 && name[:5] == "user.":
		return XattrUser
	case name == "system.posix_acl_access" || name == "system.posix_acl_default":
		return XattrACL
	case len(name) > 9 && name[:9] == "security.",
		len(name) > 8 && name[:8] == "trusted.",
		len(name) > 7 && name[:7] == "system.":
		return XattrPrivileged
	default:
		return XattrPlain
	}
}
