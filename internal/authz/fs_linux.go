//go:build linux

package authz

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func isSymlinkOpenError(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}

const (
	ext4SuperMagic      uint64 = 0xef53
	xfsSbMagic          uint64 = 0x58465342
	tmpfsMagic          uint64 = 0x01021994
	btrfsSuperMagic     uint64 = 0x9123683e
	overlayfsSuperMagic uint64 = 0x794c7630
)

func verifyLocalFilesystem(fd int) error {
	var sfs syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &sfs); err != nil {
		return NewError(ErrTCBFilesystemUnsupported, 0, "fstatfs failed: %v", err)
	}
	switch uint64(sfs.Type) {
	case ext4SuperMagic, xfsSbMagic, tmpfsMagic, btrfsSuperMagic, overlayfsSuperMagic:
		return nil
	default:
		return NewError(ErrTCBFilesystemUnsupported, 0, "unsupported filesystem magic 0x%x on linux", uint64(sfs.Type))
	}
}

func execPathForVerifiedFD(fd int, _ string) (string, error) {
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	if _, err := os.Stat(procPath); err != nil {
		return "", NewError(ErrManifestPinMismatch, 0, "/proc/self/fd/%d unavailable: %v", fd, err)
	}
	return procPath, nil
}
