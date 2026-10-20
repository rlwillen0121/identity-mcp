//go:build darwin

package authz

import (
	"errors"
	"syscall"
)

func isSymlinkOpenError(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EFTYPE)
}

func verifyLocalFilesystem(fd int) error {
	var sfs syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &sfs); err != nil {
		return NewError(ErrTCBFilesystemUnsupported, 0, "fstatfs failed: %v", err)
	}
	var buf []byte
	for _, b := range sfs.Fstypename {
		if b == 0 {
			break
		}
		buf = append(buf, byte(b))
	}
	fsType := string(buf)
	if fsType != "apfs" && fsType != "hfs" {
		return NewError(ErrTCBFilesystemUnsupported, 0, "unsupported filesystem %q on darwin (requires apfs or hfs)", fsType)
	}
	return nil
}

func execPathForVerifiedFD(_ int, fallbackPath string) (string, error) {
	return fallbackPath, nil
}
