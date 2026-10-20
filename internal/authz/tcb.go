//go:build unix

package authz

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

var envKeyRegex = regexp.MustCompile(`^[A-Z0-9_]{1,64}$`)

// ValidateCanonicalPath verifies that p is a clean, absolute path.
func ValidateCanonicalPath(p string) error {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return NewError(ErrTCBInvalidPath, 0, "path %q must be a clean canonical absolute path", p)
	}
	return nil
}

// walkVerifiedAncestors walks every ancestor directory from filepath.Dir(p) up to "/"
// and enforces: no symlinks, owner is root (0) or os.Geteuid(), and no group/world write bits (0o022).
func walkVerifiedAncestors(p string) error {
	euid := uint32(os.Geteuid())
	var testTempRoot string
	if testing.Testing() {
		if resolved, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
			testTempRoot = filepath.Clean(resolved)
		}
	}

	// Collect ancestors from immediate parent up to "/"
	dir := filepath.Dir(p)
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return NewError(ErrTCBInvalidPath, 0, "lstat ancestor directory %q: %v", dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return NewError(ErrTCBSymlinkForbidden, 0, "ancestor directory %q is a symlink", dir)
		}
		if !info.IsDir() {
			return NewError(ErrTCBInvalidPath, 0, "ancestor %q is not a directory", dir)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return NewError(ErrTCBInvalidPath, 0, "cannot read syscall.Stat_t for %q", dir)
		}
		if st.Uid != 0 && st.Uid != euid {
			return NewError(ErrTCBOwnerMismatch, 0, "ancestor directory %q owned by uid %d (expected 0 or %d)", dir, st.Uid, euid)
		}
		exemptTempRoot := testTempRoot != "" && (dir == testTempRoot || strings.HasPrefix(testTempRoot, dir+"/") || dir == "/")
		if !exemptTempRoot && (info.Mode().Perm()&0o022 != 0) {
			return NewError(ErrTCBPermissionsTooOpen, 0, "ancestor directory %q has group/other write permissions (%#o)", dir, info.Mode().Perm())
		}
		if dir == "/" {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}

// AllowedConfigUIDs returns the acceptable owner UIDs for policy.json and lockfile.
func AllowedConfigUIDs(pol *PolicyV1) []uint32 {
	if pol != nil && pol.TCB.IsolationMode == "mode_b_uid_boundary" && !(pol.TCB.AllowSameUIDInGoTest && testing.Testing()) {
		return []uint32{0}
	}
	return []uint32{0, uint32(os.Geteuid())}
}

// AllowedServiceUIDs returns the acceptable owner UIDs for state.db, audit.jsonl, env_file, and challenge_dir.
func AllowedServiceUIDs(pol *PolicyV1) []uint32 {
	if pol != nil && pol.TCB.IsolationMode == "mode_b_uid_boundary" && !(pol.TCB.AllowSameUIDInGoTest && testing.Testing()) {
		return []uint32{uint32(pol.TCB.ServiceUID)}
	}
	return []uint32{0, uint32(os.Geteuid())}
}

// OpenVerifiedFile validates canonical path + ancestor directories, opens p with O_NOFOLLOW|O_CLOEXEC,
// verifies regular file mode, owner UID, permission mask, and local filesystem type via Fstat/Fstatfs.
func OpenVerifiedFile(p string, flags int, createPerm uint32, expectedUIDs []uint32, forbiddenPermMask os.FileMode) (*os.File, syscall.Stat_t, error) {
	var zeroStat syscall.Stat_t
	if err := ValidateCanonicalPath(p); err != nil {
		return nil, zeroStat, err
	}
	if err := walkVerifiedAncestors(p); err != nil {
		return nil, zeroStat, err
	}

	fd, err := syscall.Open(p, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, createPerm)
	if err != nil {
		if isSymlinkOpenError(err) {
			return nil, zeroStat, NewError(ErrTCBSymlinkForbidden, 0, "file %q is a symlink", p)
		}
		return nil, zeroStat, err
	}

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return nil, zeroStat, NewError(ErrTCBInvalidPath, 0, "fstat %q: %v", p, err)
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFREG {
		_ = syscall.Close(fd)
		return nil, zeroStat, NewError(ErrTCBInvalidPath, 0, "path %q is not a regular file", p)
	}
	if st.Nlink > 1 {
		_ = syscall.Close(fd)
		return nil, zeroStat, NewError(ErrTCBSymlinkForbidden, 0, "file %q has multiple hardlinks (nlink=%d)", p, st.Nlink)
	}
	if len(expectedUIDs) > 0 && !slices.Contains(expectedUIDs, st.Uid) {
		_ = syscall.Close(fd)
		return nil, zeroStat, NewError(ErrTCBOwnerMismatch, 0, "file %q owned by uid %d (allowed: %v)", p, st.Uid, expectedUIDs)
	}
	perm := os.FileMode(st.Mode & 0o777)
	if perm&forbiddenPermMask != 0 {
		_ = syscall.Close(fd)
		return nil, zeroStat, NewError(ErrTCBPermissionsTooOpen, 0, "file %q permissions %#o violate forbidden mask %#o", p, perm, forbiddenPermMask)
	}
	if err := verifyLocalFilesystem(fd); err != nil {
		_ = syscall.Close(fd)
		return nil, zeroStat, err
	}

	f := os.NewFile(uintptr(fd), p)
	return f, st, nil
}

// ReadVerifiedFile reads the entire contents of a verified file up to maxBytes.
func ReadVerifiedFile(p string, expectedUIDs []uint32, forbiddenPermMask os.FileMode, maxBytes int) ([]byte, error) {
	f, st, err := OpenVerifiedFile(p, syscall.O_RDONLY, 0, expectedUIDs, forbiddenPermMask)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size > int64(maxBytes) {
		return nil, NewError(ErrPayloadTooLarge, 0, "file %q size %d exceeds %d bytes", p, st.Size, maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, NewError(ErrPayloadTooLarge, 0, "file %q exceeds %d bytes", p, maxBytes)
	}
	return data, nil
}

// VerifyDirectoryTCB verifies that dir is a canonical, non-symlink directory on an allowed local
// filesystem with owner in expectedUIDs and permissions satisfying forbiddenPermMask.
func VerifyDirectoryTCB(dir string, expectedUIDs []uint32, forbiddenPermMask os.FileMode) error {
	return verifyDirectoryTCBInternal(dir, expectedUIDs, forbiddenPermMask, false)
}

// VerifyEmptyDirectoryTCB verifies directory TCB properties and checks emptiness using the same open directory FD.
func VerifyEmptyDirectoryTCB(dir string, expectedUIDs []uint32, forbiddenPermMask os.FileMode) error {
	return verifyDirectoryTCBInternal(dir, expectedUIDs, forbiddenPermMask, true)
}

func verifyDirectoryTCBInternal(dir string, expectedUIDs []uint32, forbiddenPermMask os.FileMode, requireEmpty bool) error {
	if err := ValidateCanonicalPath(dir); err != nil {
		return err
	}
	if err := walkVerifiedAncestors(dir); err != nil {
		return err
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if isSymlinkOpenError(err) {
			return NewError(ErrTCBSymlinkForbidden, 0, "directory %q is a symlink", dir)
		}
		return NewError(ErrTCBInvalidPath, 0, "open directory %q: %v", dir, err)
	}
	dirFile := os.NewFile(uintptr(fd), dir)
	defer dirFile.Close()

	var st syscall.Stat_t
	if err := syscall.Fstat(int(dirFile.Fd()), &st); err != nil {
		return NewError(ErrTCBInvalidPath, 0, "fstat directory %q: %v", dir, err)
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFDIR {
		return NewError(ErrTCBInvalidPath, 0, "path %q is not a directory", dir)
	}
	if len(expectedUIDs) > 0 && !slices.Contains(expectedUIDs, st.Uid) {
		return NewError(ErrTCBOwnerMismatch, 0, "directory %q owned by uid %d (allowed: %v)", dir, st.Uid, expectedUIDs)
	}
	perm := os.FileMode(st.Mode & 0o777)
	if perm&forbiddenPermMask != 0 {
		return NewError(ErrTCBPermissionsTooOpen, 0, "directory %q permissions %#o violate forbidden mask %#o", dir, perm, forbiddenPermMask)
	}
	if err := verifyLocalFilesystem(int(dirFile.Fd())); err != nil {
		return err
	}
	if requireEmpty {
		names, err := dirFile.Readdirnames(1)
		if err != nil && err != io.EOF {
			return NewError(ErrTCBInvalidPath, 0, "readdir empty_home_dir %q: %v", dir, err)
		}
		if len(names) != 0 {
			return NewError(ErrTCBInvalidPath, 0, "tcb.empty_home_dir %q must be empty", dir)
		}
	}
	return nil
}

// FsyncDir flushes directory metadata after atomic rename/create operations.
func FsyncDir(dir string) error {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Fsync(fd)
}

// VerifyTCBIsolationMode enforces §2.1.1 Mode A vs Mode B isolation requirements.
func VerifyTCBIsolationMode(pol *PolicyV1) error {
	if pol.TCB.AllowSameUIDInGoTest && !testing.Testing() {
		return NewError(ErrTestFlagForbiddenInProd, 0, "tcb.allow_same_uid_in_go_test cannot be enabled outside go test")
	}

	hasWriteTool := false
	for _, t := range pol.Tools {
		if t.Enabled && (t.ActionClass == "write:low-risk" || t.ActionClass == "write:high-risk") {
			hasWriteTool = true
			break
		}
	}

	switch pol.TCB.IsolationMode {
	case "mode_a_read_only":
		if hasWriteTool {
			return NewError(ErrModeAWriteForbidden, 0, "isolation_mode \"mode_a_read_only\" is forbidden when any write tool is enabled")
		}
		return nil

	case "mode_b_uid_boundary":
		if pol.TCB.ServiceUID <= 0 {
			return NewError(ErrTCBUIDBoundaryRequired, 0, "mode_b_uid_boundary requires positive tcb.service_uid")
		}
		if len(pol.TCB.ForbiddenUIDs) == 0 {
			return NewError(ErrTCBUIDBoundaryRequired, 0, "mode_b_uid_boundary requires non-empty tcb.forbidden_uids")
		}
		if slices.Contains(pol.TCB.ForbiddenUIDs, pol.TCB.ServiceUID) {
			return NewError(ErrTCBUIDBoundaryRequired, 0, "tcb.service_uid %d cannot appear in tcb.forbidden_uids", pol.TCB.ServiceUID)
		}
		if pol.TCB.AllowSameUIDInGoTest && testing.Testing() {
			return nil
		}
		euid := os.Geteuid()
		if euid != pol.TCB.ServiceUID || slices.Contains(pol.TCB.ForbiddenUIDs, euid) {
			return NewError(ErrTCBUIDBoundaryRequired, 0, "process euid %d must equal service_uid %d and not be in forbidden_uids %v", euid, pol.TCB.ServiceUID, pol.TCB.ForbiddenUIDs)
		}
		if sudoUIDStr, ok := os.LookupEnv("SUDO_UID"); ok {
			sudoUID, err := strconv.Atoi(sudoUIDStr)
			if err != nil || sudoUID == pol.TCB.ServiceUID || !slices.Contains(pol.TCB.ForbiddenUIDs, sudoUID) {
				return NewError(ErrTCBUIDBoundaryRequired, 0, "SUDO_UID %q is not an authorized caller in tcb.forbidden_uids", sudoUIDStr)
			}
		}
		return nil

	default:
		return NewError(ErrTCBUIDBoundaryRequired, 0, "unsupported tcb.isolation_mode %q", pol.TCB.IsolationMode)
	}
}

// VerifyPolicyAndLockfileSignature verifies the optional detached Ed25519 signature over
// "MCP-AUTHZ-CONFIG-V1\n" || JCS(policy.json) || "\n" || JCS(mcp-authz.lock.json).
func VerifyPolicyAndLockfileSignature(pol *PolicyV1, rawPolicyJSON []byte, rawLockfileJSON []byte) error {
	if pol.TCB.AdminPubKey == "" && pol.TCB.PolicySigPath == "" {
		return nil
	}
	if pol.TCB.AdminPubKey == "" || pol.TCB.PolicySigPath == "" {
		return NewError(ErrPolicySignatureInvalid, 0, "both tcb.admin_pubkey and tcb.policy_sig_path must be set when config signing is used")
	}
	pubKey, err := ParseEd25519PubKeySpec(pol.TCB.AdminPubKey)
	if err != nil {
		return NewError(ErrPolicySignatureInvalid, 0, "invalid tcb.admin_pubkey: %v", err)
	}
	sigRaw, err := ReadVerifiedFile(pol.TCB.PolicySigPath, AllowedConfigUIDs(pol), 0o022, 4096)
	if err != nil {
		return NewError(ErrPolicySignatureInvalid, 0, "cannot read policy_sig_path: %v", err)
	}
	sigStr := strings.TrimSpace(string(sigRaw))
	sigBytes, err := hex.DecodeString(sigStr)
	if err != nil {
		sigBytes, err = base64.RawURLEncoding.DecodeString(sigStr)
		if err != nil {
			return NewError(ErrPolicySignatureInvalid, 0, "policy signature must be hex or base64url encoded")
		}
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return NewError(ErrPolicySignatureInvalid, 0, "policy signature length %d != %d", len(sigBytes), ed25519.SignatureSize)
	}

	polVal, err := DecodeStrictJSONWithCap(rawPolicyJSON, MaxConfigFileBytes, false)
	if err != nil {
		return NewError(ErrPolicySignatureInvalid, 0, "decode policy for signature: %v", err)
	}
	polJCS, err := MarshalJCS(polVal)
	if err != nil {
		return NewError(ErrPolicySignatureInvalid, 0, "JCS policy: %v", err)
	}
	lockVal, err := DecodeStrictJSONWithCap(rawLockfileJSON, MaxConfigFileBytes, false)
	if err != nil {
		return NewError(ErrPolicySignatureInvalid, 0, "decode lockfile for signature: %v", err)
	}
	lockJCS, err := MarshalJCS(lockVal)
	if err != nil {
		return NewError(ErrPolicySignatureInvalid, 0, "JCS lockfile: %v", err)
	}

	msg := ComputeConfigSignatureMessage(polJCS, lockJCS)
	if !ed25519.Verify(pubKey, msg, sigBytes) {
		return NewError(ErrPolicySignatureInvalid, 0, "Ed25519 signature verification failed for policy + lockfile")
	}
	return nil
}

// ComputeConfigSignatureMessage builds the canonical signing preimage for policy + lockfile.
func ComputeConfigSignatureMessage(polJCS, lockJCS []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("MCP-AUTHZ-CONFIG-V1\n")
	buf.Write(polJCS)
	buf.WriteByte('\n')
	buf.Write(lockJCS)
	return buf.Bytes()
}

func isForbiddenEnvKey(k string) bool {
	if !envKeyRegex.MatchString(k) {
		return true
	}
	switch k {
	case "GODEBUG", "GOFLAGS", "GOPATH", "GOROOT", "PATH", "HOME", "LANG", "TZ":
		return true
	}
	for _, prefix := range []string{"MCP_AUTHZ_", "LD_", "DYLD_", "SSL_CERT_"} {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	if strings.HasSuffix(k, "_PROXY") || strings.HasSuffix(asciiLower(k), "_proxy") {
		return true
	}
	return false
}

// ValidateEnvPolicy checks upstream.pass_env and upstream.secret_env_keys at policy load time.
func ValidateEnvPolicy(up *UpstreamConfig) error {
	for _, k := range up.PassEnv {
		if isForbiddenEnvKey(k) {
			return NewError(ErrForbiddenPassEnv, 0, "upstream.pass_env key %q is forbidden", k)
		}
	}
	if len(up.SecretEnvKeys) == 0 {
		return NewError(ErrInvalidSecretEnvValue, 0, "upstream.secret_env_keys must be non-empty")
	}
	for _, sk := range up.SecretEnvKeys {
		if isForbiddenEnvKey(sk) {
			return NewError(ErrForbiddenPassEnv, 0, "upstream.secret_env_keys key %q is forbidden", sk)
		}
		if !slices.Contains(up.PassEnv, sk) {
			return NewError(ErrInvalidSecretEnvValue, 0, "secret_env_keys entry %q must also appear in upstream.pass_env", sk)
		}
	}
	return nil
}

// BuildChildEnv constructs the scrubbed child environment from policy.Upstream.EnvFile
// and returns (envSlice, secretValuesMap, error).
func BuildChildEnv(pol *PolicyV1) ([]string, map[string]string, error) {
	if err := ValidateEnvPolicy(&pol.Upstream); err != nil {
		return nil, nil, err
	}

	// Verify empty_home_dir exists, has 0700 permissions, and is empty on the same open directory FD.
	if err := VerifyEmptyDirectoryTCB(pol.TCB.EmptyHomeDir, AllowedServiceUIDs(pol), 0o077); err != nil {
		return nil, nil, err
	}

	envMap := make(map[string]string)
	if pol.Upstream.EnvFile != "" {
		rawEnv, err := ReadVerifiedFile(pol.Upstream.EnvFile, AllowedServiceUIDs(pol), 0o177, 65536)
		if err != nil {
			return nil, nil, err
		}
		lines := strings.Split(string(rawEnv), "\n")
		for lineNo, line := range lines {
			line = strings.TrimSuffix(line, "\r")
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.HasPrefix(line, "export ") {
				return nil, nil, NewError(ErrForbiddenPassEnv, 0, "env_file line %d: 'export' prefix is forbidden", lineNo+1)
			}
			eqIdx := strings.IndexByte(line, '=')
			if eqIdx <= 0 {
				return nil, nil, NewError(ErrForbiddenPassEnv, 0, "env_file line %d: missing '='", lineNo+1)
			}
			key := line[:eqIdx]
			val := line[eqIdx+1:]
			if isForbiddenEnvKey(key) {
				return nil, nil, NewError(ErrForbiddenPassEnv, 0, "env_file line %d: forbidden or malformed key %q", lineNo+1, key)
			}
			if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
				return nil, nil, NewError(ErrForbiddenPassEnv, 0, "env_file line %d: quoted values are forbidden", lineNo+1)
			}
			for i := 0; i < len(val); i++ {
				if val[i] < 0x20 || val[i] == 0x7F {
					return nil, nil, NewError(ErrForbiddenPassEnv, 0, "env_file line %d: control character in value", lineNo+1)
				}
			}
			envMap[key] = val
		}
	}

	secretValues := make(map[string]string, len(pol.Upstream.SecretEnvKeys))
	for _, sk := range pol.Upstream.SecretEnvKeys {
		v, ok := envMap[sk]
		if !ok || len(v) < 16 || len(v) > 8192 {
			return nil, nil, NewError(ErrInvalidSecretEnvValue, 0, "secret_env_keys entry %q must be present in env_file with length in [16, 8192] bytes", sk)
		}
		secretValues[sk] = v
	}

	childEnv := []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + pol.TCB.EmptyHomeDir,
		"LANG=C.UTF-8",
		"TZ=UTC",
	}
	if pol.TCB.SSLCertFile != "" {
		certFile, _, err := OpenVerifiedFile(pol.TCB.SSLCertFile, syscall.O_RDONLY, 0, AllowedConfigUIDs(pol), 0o022)
		if err != nil {
			return nil, nil, err
		}
		_ = certFile.Close()
		childEnv = append(childEnv, "SSL_CERT_FILE="+pol.TCB.SSLCertFile)
	}
	if pol.TCB.SSLCertDir != "" {
		if err := VerifyDirectoryTCB(pol.TCB.SSLCertDir, AllowedConfigUIDs(pol), 0o022); err != nil {
			return nil, nil, err
		}
		childEnv = append(childEnv, "SSL_CERT_DIR="+pol.TCB.SSLCertDir)
	}
	for _, k := range pol.Upstream.PassEnv {
		if v, ok := envMap[k]; ok {
			childEnv = append(childEnv, k+"="+v)
		}
	}
	return childEnv, secretValues, nil
}
