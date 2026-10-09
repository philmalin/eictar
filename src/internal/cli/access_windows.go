//go:build windows

package cli

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows, the owner and the ACL of a file give who can read and write it
// (doc/design.md 11.4 and 15.1). The program trusts you, SYSTEM and the
// Administrators group, as it trusts you and root on Unix.

const (
	// The rights that let an account read the content, or write it. WRITE_DAC
	// and WRITE_OWNER are in both, because with them an account can give
	// itself the other rights.
	readRights  = windows.FILE_READ_DATA | windows.WRITE_DAC | windows.WRITE_OWNER
	writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.WRITE_DAC | windows.WRITE_OWNER

	// ACCESS_ALLOWED_CALLBACK_ACE_TYPE: an allow with a condition. The
	// program does not evaluate the condition, and counts the allow.
	aceAllowedCallback = 9
)

// checkConfigOwner refuses a configuration file that another account owns,
// or that another account can write.
func checkConfigOwner(f *os.File, _ os.FileInfo) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot read its access control list: %w; refusing to use it", err)
	}
	you, err := currentUser()
	if err != nil {
		return err
	}
	owner, writers, err := exposure(sd, you, writeRights)
	if err != nil {
		return fmt.Errorf("cannot read its access control list: %w; refusing to use it", err)
	}
	if owner != nil {
		return fmt.Errorf("it is owned by %s, not by you; refusing to use it", accountName(owner))
	}
	if len(writers) > 0 {
		return fmt.Errorf("%s can write it; refusing to use it", accountNames(writers))
	}
	return nil
}

// passphraseFileExposure gives the warning for a passphrase file that
// another account owns or can read, or "" (doc/Security_Audit.md, finding 8).
func passphraseFileExposure(path string) string {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ""
	}
	you, err := currentUser()
	if err != nil {
		return ""
	}
	owner, readers, err := exposure(sd, you, readRights)
	switch {
	case err != nil:
		return ""
	case owner != nil:
		return fmt.Sprintf("%s is owned by %s, who can read it; give only your account access to it", path, accountName(owner))
	case len(readers) > 0:
		return fmt.Sprintf("%s can be read by %s; give only your account access to it", path, accountNames(readers))
	}
	return ""
}

func currentUser() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("cannot read your account: %w", err)
	}
	return u.User.Sid, nil
}

// exposure gives the owner of sd if that owner is not trusted, and the
// accounts that are not trusted and that the DACL gives one of the rights in
// mask. you is the account of this process.
//
// The check reads the ACEs in order, as Windows does. A deny takes away a
// right from later allows of the same account, and a deny to Everyone takes
// it away from all. A deny to a group does not take away the right from a
// member of that group, because the program does not know the members. Thus
// the check can report an account that Windows stops, but it does not miss
// one that Windows lets through.
func exposure(sd *windows.SECURITY_DESCRIPTOR, you *windows.SID, mask windows.ACCESS_MASK) (owner *windows.SID, others []*windows.SID, err error) {
	if o, _, err := sd.Owner(); err != nil {
		return nil, nil, err
	} else if o != nil && !trusted(o, you) {
		owner = o
	}

	dacl, _, err := sd.DACL()
	if err == windows.ERROR_OBJECT_NOT_FOUND || err == nil && dacl == nil {
		// No DACL, or a NULL DACL: each account has each right.
		everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
		if err != nil {
			return nil, nil, err
		}
		return owner, []*windows.SID{everyone}, nil
	} else if err != nil {
		return nil, nil, err
	}

	var deniedToAll windows.ACCESS_MASK
	denied := map[string]windows.ACCESS_MASK{}
	seen := map[string]bool{}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, nil, err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // applies only to the children of a directory
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		key := sid.String()
		rights := expandGeneric(ace.Mask) & mask
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			if sid.IsWellKnown(windows.WinWorldSid) {
				deniedToAll |= rights
			} else {
				denied[key] |= rights
			}
		case windows.ACCESS_ALLOWED_ACE_TYPE, aceAllowedCallback:
			if rights&^deniedToAll&^denied[key] != 0 && !trusted(sid, you) && !seen[key] {
				seen[key] = true
				c, err := sid.Copy()
				if err != nil {
					return nil, nil, err
				}
				others = append(others, c)
			}
		}
	}
	return owner, others, nil
}

// trusted: you, SYSTEM and the Administrators group. CREATOR OWNER has an
// effect only in an inherited ACE, and OWNER RIGHTS applies to the owner,
// whom the check reports on its own.
func trusted(sid, you *windows.SID) bool {
	return sid.Equals(you) ||
		sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.IsWellKnown(windows.WinCreatorOwnerSid) ||
		sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)
}

// expandGeneric changes the generic rights into the file rights that they
// give.
func expandGeneric(m windows.ACCESS_MASK) windows.ACCESS_MASK {
	if m&windows.GENERIC_ALL != 0 {
		m |= windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.WRITE_DAC | windows.WRITE_OWNER
	}
	if m&windows.GENERIC_READ != 0 {
		m |= windows.FILE_READ_DATA
	}
	if m&windows.GENERIC_WRITE != 0 {
		m |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	return m
}

// accountName gives DOMAIN\name, or the SID if Windows cannot find the
// account.
func accountName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	switch {
	case err != nil:
		return sid.String()
	case domain == "":
		return account
	}
	return domain + `\` + account
}

func accountNames(sids []*windows.SID) string {
	names := make([]string, len(sids))
	for i, s := range sids {
		names[i] = accountName(s)
	}
	return strings.Join(names, ", ")
}
