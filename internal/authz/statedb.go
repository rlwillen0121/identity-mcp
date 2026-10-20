//go:build unix

package authz

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	MaxStateDBCompactionBytes = 4 * 1024 * 1024  // 4 MiB
	MaxLedgerFileBytes        = 64 * 1024 * 1024 // 64 MiB
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// StateDBRecordV1 is the CRC32C-framed record format for state.db (§4.4.3).
type StateDBRecordV1 struct {
	Version   string `json:"ver"`
	LedgerID  string `json:"ledger_id"`
	Kind      string `json:"kind"` // "header" | "audit_hwm" | "replay" | "budget" | "grant" | "grant_revoke" | "challenge"
	GatewayID string `json:"gateway_id"`
	Key       string `json:"key"`
	SubKey    string `json:"sub_key,omitempty"`
	Value     string `json:"value,omitempty"`
	Count     int    `json:"count,omitempty"`
	AuditSeq  uint64 `json:"audit_seq,omitempty"`
	AuditHash string `json:"audit_hash,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	CRC32C    string `json:"crc32c,omitempty"`
}

// ComputeStateRecordCRC computes the 8-char lowercase hex Castagnoli CRC32C over JCS(rec_without_crc32c).
func ComputeStateRecordCRC(rec StateDBRecordV1) (string, error) {
	copyRec := rec
	copyRec.CRC32C = ""
	jcsBytes, err := MarshalJCS(copyRec)
	if err != nil {
		return "", err
	}
	sum := crc32.Checksum(jcsBytes, crc32cTable)
	return fmt.Sprintf("%08x", sum), nil
}

// FormatStateRecordLine formats a StateDBRecordV1 with its CRC32C as a JCS JSONL line ending in '\n'.
func FormatStateRecordLine(rec StateDBRecordV1) ([]byte, error) {
	crc, err := ComputeStateRecordCRC(rec)
	if err != nil {
		return nil, err
	}
	rec.CRC32C = crc
	jcsBytes, err := MarshalJCS(rec)
	if err != nil {
		return nil, err
	}
	return append(jcsBytes, '\n'), nil
}

type budgetEntry struct {
	PrincipalID string
	Count       int
	IssuedAt    int64
	ExpiresAt   int64
}

type challengeEntry struct {
	PrincipalID string
	IssuedAt    int64
	ExpiresAt   int64
}

type parsedLedgerState struct {
	LedgerID    string
	GatewayID   string
	HWMSeq      uint64
	HWMHash     string
	Replays     map[string]StateDBRecordV1       // jti -> record
	Budgets     []budgetEntry                    // write call/target records
	Challenges  []challengeEntry                 // challenge rate limit records
	Grants      map[string]map[string]struct{}   // subject -> set of active entitlements
	GrantOrigin map[string]map[string]int64      // subject -> entitlement -> iat
}

func newParsedLedgerState() *parsedLedgerState {
	return &parsedLedgerState{
		Replays:     make(map[string]StateDBRecordV1),
		Grants:      make(map[string]map[string]struct{}),
		GrantOrigin: make(map[string]map[string]int64),
	}
}

func (s *parsedLedgerState) clone() *parsedLedgerState {
	c := newParsedLedgerState()
	c.LedgerID = s.LedgerID
	c.GatewayID = s.GatewayID
	c.HWMSeq = s.HWMSeq
	c.HWMHash = s.HWMHash
	for k, v := range s.Replays {
		c.Replays[k] = v
	}
	c.Budgets = slices.Clone(s.Budgets)
	c.Challenges = slices.Clone(s.Challenges)
	for subj, entSet := range s.Grants {
		c.Grants[subj] = make(map[string]struct{}, len(entSet))
		for e := range entSet {
			c.Grants[subj][e] = struct{}{}
		}
	}
	for subj, origMap := range s.GrantOrigin {
		c.GrantOrigin[subj] = make(map[string]int64, len(origMap))
		for e, iat := range origMap {
			c.GrantOrigin[subj][e] = iat
		}
	}
	return c
}

// InitState implements `mcp-authz-gateway init-state` (§2.1.2 & §3.2):
// creates state.db, state.db.lock, audit.jsonl, challenge_dir, and empty_home_dir,
// generates a 128-bit ledger_id, and writes genesis records.
func InitState(pol *PolicyV1, now time.Time) (string, error) {
	if now.IsZero() {
		now = time.Now()
	}
	serviceUIDs := AllowedServiceUIDs(pol)

	// Ensure directories exist with 0700 permissions
	for _, dir := range []string{
		filepath.Dir(pol.TCB.StateDBPath),
		filepath.Dir(pol.TCB.AuditLogPath),
		pol.TCB.ChallengeDir,
		pol.TCB.EmptyHomeDir,
	} {
		if err := ValidateCanonicalPath(dir); err != nil {
			return "", err
		}
		if _, err := os.Lstat(dir); os.IsNotExist(err) {
			if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
				return "", NewError(ErrTCBInvalidPath, 0, "mkdir %q: %v", dir, mkErr)
			}
		}
		if err := VerifyDirectoryTCB(dir, serviceUIDs, 0o077); err != nil {
			return "", err
		}
	}

	lockPath := pol.TCB.StateDBPath + ".lock"
	lockFile, _, err := OpenVerifiedFile(lockPath, syscall.O_CREAT|syscall.O_RDWR, 0o600, serviceUIDs, 0o177)
	if err != nil {
		return "", err
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return "", NewError(ErrStateLedgerUnavailable, 0, "flock %q: %v", lockPath, err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	// Refuse if state.db or audit.jsonl already exists and is non-empty
	for _, p := range []string{pol.TCB.StateDBPath, pol.TCB.AuditLogPath} {
		if info, err := os.Lstat(p); err == nil && info.Size() > 0 {
			return "", NewError(ErrStateLedgerUnavailable, 0, "cannot init-state: %q already exists and is non-empty", p)
		}
	}

	var randID [16]byte
	if _, err := rand.Read(randID[:]); err != nil {
		return "", err
	}
	ledgerID := hex.EncodeToString(randID[:])
	nowUnix := now.Unix()

	// Create and write genesis audit record (seq = 1)
	auditFile, _, err := OpenVerifiedFile(pol.TCB.AuditLogPath, syscall.O_CREAT|syscall.O_TRUNC|syscall.O_RDWR, 0o600, serviceUIDs, 0o177)
	if err != nil {
		return "", err
	}
	defer auditFile.Close()

	genesisAudit := AuditRecordV1{
		Seq:             1,
		Timestamp:       now.UTC().Format(time.RFC3339Nano),
		GatewayID:       pol.GatewayID,
		LedgerID:        ledgerID,
		ServerName:      pol.ServerName,
		ToolName:        "_system",
		ActionClass:     "system",
		Decision:        "ledger_initialized",
		Stage:           0,
		ErrorCode:       "",
		PrincipalID:     "_system",
		PrincipalSub:    "_system",
		PrincipalEmail:  "",
		EffectiveScopes: []string{},
		RedactedArgs:    map[string]any{},
		PrevHash:        AuditGenesisZeros,
	}
	genHash, err := ComputeAuditRecordHash(genesisAudit)
	if err != nil {
		return "", err
	}
	genesisAudit.RecordHash = genHash
	genAuditJCS, err := MarshalJCS(genesisAudit)
	if err != nil {
		return "", err
	}
	if _, err := auditFile.Write(append(genAuditJCS, '\n')); err != nil {
		return "", NewError(ErrAuditLogUnavailable, 0, "write genesis audit record: %v", err)
	}
	if err := auditFile.Sync(); err != nil {
		return "", NewError(ErrAuditLogUnavailable, 0, "fsync audit.jsonl: %v", err)
	}

	// Create and write genesis header + audit_hwm to state.db
	stateFile, _, err := OpenVerifiedFile(pol.TCB.StateDBPath, syscall.O_CREAT|syscall.O_TRUNC|syscall.O_RDWR, 0o600, serviceUIDs, 0o177)
	if err != nil {
		return "", err
	}
	defer stateFile.Close()

	hdrLine, err := FormatStateRecordLine(StateDBRecordV1{
		Version:   "mcp-authz-state/v1",
		LedgerID:  ledgerID,
		Kind:      "header",
		GatewayID: pol.GatewayID,
		Key:       "ledger_id",
		Value:     ledgerID,
		IssuedAt:  nowUnix,
		ExpiresAt: 0,
	})
	if err != nil {
		return "", err
	}
	hwmLine, err := FormatStateRecordLine(StateDBRecordV1{
		Version:   "mcp-authz-state/v1",
		LedgerID:  ledgerID,
		Kind:      "audit_hwm",
		GatewayID: pol.GatewayID,
		Key:       "hwm",
		AuditSeq:  1,
		AuditHash: genHash,
		IssuedAt:  nowUnix,
		ExpiresAt: 0,
	})
	if err != nil {
		return "", err
	}
	if _, err := stateFile.Write(append(hdrLine, hwmLine...)); err != nil {
		return "", NewError(ErrStateLedgerUnavailable, 0, "write genesis state.db: %v", err)
	}
	if err := stateFile.Sync(); err != nil {
		return "", NewError(ErrStateLedgerUnavailable, 0, "fsync state.db: %v", err)
	}
	_ = FsyncDir(filepath.Dir(pol.TCB.StateDBPath))
	_ = FsyncDir(filepath.Dir(pol.TCB.AuditLogPath))

	return ledgerID, nil
}

// Ledger manages unified synchronization (`ledgerMu` + `flock(state.db.lock)`) across
// both `state.db` and `audit.jsonl` (§4.4.2).
type Ledger struct {
	pol      *PolicyV1
	ledgerMu sync.Mutex
	lockFile *os.File

	// Protected by ledgerMu + flock(lockFile):
	cachedDev   uint64
	cachedIno   uint64
	cachedSize  int64
	cachedState *parsedLedgerState

	// Test hook to simulate a process crash between audit.jsonl fsync and state.db audit_hwm fsync.
	SkipNextHWMUpdateForTest bool
}

// OpenLedger opens an initialized state.db.lock and verifies both state.db and audit.jsonl
// (recovering a 1-record HWM lag if the previous process crashed between audit fsync and hwm fsync).
func OpenLedger(pol *PolicyV1) (*Ledger, error) {
	serviceUIDs := AllowedServiceUIDs(pol)
	lockPath := pol.TCB.StateDBPath + ".lock"
	lockFile, _, err := OpenVerifiedFile(lockPath, syscall.O_RDWR, 0, serviceUIDs, 0o177)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, syscall.ENOENT) {
			return nil, NewError(ErrStateLedgerUninitialized, 0, "state lockfile %q does not exist (run init-state first)", lockPath)
		}
		return nil, err
	}

	l := &Ledger{
		pol:      pol,
		lockFile: lockFile,
	}
	if err := l.verifyStartupAndRecoverHWM(); err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	return l, nil
}

// Close closes the underlying lock descriptor.
func (l *Ledger) Close() error {
	l.ledgerMu.Lock()
	defer l.ledgerMu.Unlock()
	if l.lockFile != nil {
		err := l.lockFile.Close()
		l.lockFile = nil
		return err
	}
	return nil
}

// LedgerID returns the active 128-bit ledger_id.
func (l *Ledger) LedgerID() (string, error) {
	var id string
	err := l.withExclusiveLock(func(_ *os.File, _ *os.File, st *parsedLedgerState) error {
		id = st.LedgerID
		return nil
	})
	return id, err
}

// ActiveGrantsSnapshot returns a copy of active permanent SoD grants under the unified lock.
func (l *Ledger) ActiveGrantsSnapshot() (string, map[string]map[string]struct{}, error) {
	var ledgerID string
	var grants map[string]map[string]struct{}
	err := l.withExclusiveLock(func(_ *os.File, _ *os.File, st *parsedLedgerState) error {
		ledgerID = st.LedgerID
		cloned := st.clone()
		grants = cloned.Grants
		return nil
	})
	return ledgerID, grants, err
}

// withExclusiveLock executes fn under the single process-wide ledgerMu and OS flock(state.db.lock),
// opening fresh verified file descriptors for state.db and audit.jsonl and validating `(dev, ino, size)`.
func (l *Ledger) withExclusiveLock(fn func(stateFile *os.File, auditFile *os.File, state *parsedLedgerState) error) error {
	l.ledgerMu.Lock()
	defer l.ledgerMu.Unlock()

	if l.lockFile == nil {
		return NewError(ErrStateLedgerUnavailable, 4, "ledger is closed")
	}
	lockFd := int(l.lockFile.Fd())
	if err := syscall.Flock(lockFd, syscall.LOCK_EX); err != nil {
		return NewError(ErrStateLedgerUnavailable, 4, "flock state.db.lock failed: %v", err)
	}
	defer syscall.Flock(lockFd, syscall.LOCK_UN)

	serviceUIDs := AllowedServiceUIDs(l.pol)
	stateFile, stateStat, err := OpenVerifiedFile(l.pol.TCB.StateDBPath, syscall.O_RDWR|syscall.O_APPEND, 0, serviceUIDs, 0o177)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, syscall.ENOENT) {
			return NewError(ErrStateLedgerUninitialized, 0, "state.db %q does not exist (run init-state first)", l.pol.TCB.StateDBPath)
		}
		return err
	}
	defer stateFile.Close()

	auditFile, auditStat, err := OpenVerifiedFile(l.pol.TCB.AuditLogPath, syscall.O_RDWR|syscall.O_APPEND, 0, serviceUIDs, 0o177)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, syscall.ENOENT) {
			return NewError(ErrAuditLogUninitialized, 0, "audit.jsonl %q does not exist (run init-state first)", l.pol.TCB.AuditLogPath)
		}
		return err
	}
	defer auditFile.Close()

	if stateStat.Size == 0 {
		return NewError(ErrStateLedgerUninitialized, 0, "state.db is empty (run init-state first)")
	}
	if stateStat.Size > MaxLedgerFileBytes {
		return NewError(ErrPayloadTooLarge, 4, "state.db size %d exceeds %d bytes", stateStat.Size, MaxLedgerFileBytes)
	}
	if auditStat.Size == 0 {
		return NewError(ErrAuditLogUninitialized, 0, "audit.jsonl is empty (run init-state first)")
	}
	if auditStat.Size > MaxLedgerFileBytes {
		return NewError(ErrPayloadTooLarge, 4, "audit.jsonl size %d exceeds %d bytes", auditStat.Size, MaxLedgerFileBytes)
	}

	curDev := uint64(stateStat.Dev)
	curIno := uint64(stateStat.Ino)
	curSize := stateStat.Size

	var activeState *parsedLedgerState
	if l.cachedState != nil && curDev == l.cachedDev && curIno == l.cachedIno && curSize >= l.cachedSize {
		activeState = l.cachedState.clone()
		if curSize > l.cachedSize {
			deltaBytes := make([]byte, curSize-l.cachedSize)
			if _, err := stateFile.ReadAt(deltaBytes, l.cachedSize); err != nil && err != io.EOF {
				return NewError(ErrStateLedgerUnavailable, 4, "read state.db delta: %v", err)
			}
			if err := applyStateRecordsBytes(activeState, deltaBytes, l.pol.GatewayID, false); err != nil {
				return err
			}
			l.cachedState = activeState.clone()
			l.cachedSize = curSize
		}
	} else {
		// Cache cold or (dev, ino) changed after another process ran compaction rename!
		fullBytes := make([]byte, curSize)
		if _, err := stateFile.ReadAt(fullBytes, 0); err != nil && err != io.EOF {
			return NewError(ErrStateLedgerUnavailable, 4, "read state.db: %v", err)
		}
		freshState := newParsedLedgerState()
		if err := applyStateRecordsBytes(freshState, fullBytes, l.pol.GatewayID, true); err != nil {
			return err
		}
		l.cachedDev = curDev
		l.cachedIno = curIno
		l.cachedSize = curSize
		l.cachedState = freshState.clone()
		activeState = freshState
	}

	return fn(stateFile, auditFile, activeState)
}

func applyStateRecordsBytes(st *parsedLedgerState, data []byte, expectedGatewayID string, requireHeader bool) error {
	if len(data) == 0 {
		if requireHeader {
			return NewError(ErrStateLedgerUninitialized, 0, "state.db is empty")
		}
		return nil
	}
	if data[len(data)-1] != '\n' {
		return NewError(ErrStateLedgerUnavailable, 4, "state.db has incomplete final line (missing trailing newline)")
	}
	lines := bytes.Split(data[:len(data)-1], []byte{'\n'})
	for idx, line := range lines {
		rec, err := parseAndVerifyStateRecordLine(line)
		if err != nil {
			return err
		}
		if rec.GatewayID != expectedGatewayID {
			return NewError(ErrStateLedgerUnavailable, 4, "state.db record gateway_id %q != %q", rec.GatewayID, expectedGatewayID)
		}
		if requireHeader && idx == 0 {
			if rec.Kind != "header" || rec.Key != "ledger_id" || !ledgerIDHexRegex.MatchString(rec.Value) || rec.LedgerID != rec.Value {
				return NewError(ErrStateLedgerUnavailable, 4, "state.db line 1 is not a valid genesis header record")
			}
			st.LedgerID = rec.LedgerID
			st.GatewayID = rec.GatewayID
		} else {
			if st.LedgerID == "" || rec.LedgerID != st.LedgerID {
				return NewError(ErrStateLedgerUnavailable, 4, "state.db record ledger_id %q != header ledger_id %q", rec.LedgerID, st.LedgerID)
			}
		}

		switch rec.Kind {
		case "header":
			if st.LedgerID != "" && rec.LedgerID != st.LedgerID {
				return NewError(ErrStateLedgerUnavailable, 4, "conflicting header ledger_id in state.db")
			}
		case "audit_hwm":
			if rec.AuditSeq < st.HWMSeq {
				return NewError(ErrAuditLogCorrupted, 0, "state.db audit_hwm regressed from %d to %d", st.HWMSeq, rec.AuditSeq)
			}
			st.HWMSeq = rec.AuditSeq
			st.HWMHash = rec.AuditHash
		case "replay":
			st.Replays[rec.Key] = rec
		case "budget":
			st.Budgets = append(st.Budgets, budgetEntry{
				PrincipalID: rec.Key,
				Count:       rec.Count,
				IssuedAt:    rec.IssuedAt,
				ExpiresAt:   rec.ExpiresAt,
			})
		case "challenge":
			st.Challenges = append(st.Challenges, challengeEntry{
				PrincipalID: rec.Key,
				IssuedAt:    rec.IssuedAt,
				ExpiresAt:   rec.ExpiresAt,
			})
		case "grant":
			if st.Grants[rec.Key] == nil {
				st.Grants[rec.Key] = make(map[string]struct{})
				st.GrantOrigin[rec.Key] = make(map[string]int64)
			}
			st.Grants[rec.Key][rec.SubKey] = struct{}{}
			st.GrantOrigin[rec.Key][rec.SubKey] = rec.IssuedAt
		case "grant_revoke":
			if st.Grants[rec.Key] != nil {
				delete(st.Grants[rec.Key], rec.SubKey)
				delete(st.GrantOrigin[rec.Key], rec.SubKey)
			}
		default:
			return NewError(ErrStateLedgerUnavailable, 4, "unknown state.db record kind %q", rec.Kind)
		}
	}
	if st.LedgerID == "" || st.HWMSeq == 0 || len(st.HWMHash) != 64 {
		return NewError(ErrStateLedgerUninitialized, 0, "state.db missing genesis header or audit_hwm")
	}
	return nil
}

func parseAndVerifyStateRecordLine(line []byte) (StateDBRecordV1, error) {
	var rec StateDBRecordV1
	if _, err := DecodeStrictJSONObject(line, true); err != nil {
		return rec, NewError(ErrStateLedgerUnavailable, 4, "corrupted JSON in state.db: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return rec, NewError(ErrStateLedgerUnavailable, 4, "decode StateDBRecordV1: %v", err)
	}
	if rec.Version != "mcp-authz-state/v1" {
		return rec, NewError(ErrStateLedgerUnavailable, 4, "unsupported state.db record version %q", rec.Version)
	}
	expectedCRC, err := ComputeStateRecordCRC(rec)
	if err != nil || rec.CRC32C != expectedCRC {
		return rec, NewError(ErrStateLedgerUnavailable, 4, "state.db CRC32C mismatch (got %q, expected %q)", rec.CRC32C, expectedCRC)
	}
	jcsLine, err := MarshalJCS(rec)
	if err != nil || !bytes.Equal(line, jcsLine) {
		return rec, NewError(ErrStateLedgerUnavailable, 4, "state.db record is not JCS canonical")
	}
	return rec, nil
}

// verifyStartupAndRecoverHWM verifies the full audit.jsonl hash chain against state.db's audit_hwm
// and recovers a 1-record HWM lag if the previous process crashed between fsync(audit) and fsync(state).
func (l *Ledger) verifyStartupAndRecoverHWM() error {
	return l.withExclusiveLock(func(stateFile *os.File, auditFile *os.File, st *parsedLedgerState) error {
		tailSeq, tailPrevHash, tailHash, err := verifyAuditChainFile(auditFile, l.pol.GatewayID, st.LedgerID)
		if err != nil {
			return err
		}
		if tailSeq == st.HWMSeq && tailHash == st.HWMHash {
			return nil
		}
		// §4.6.3 1-Record HWM Crash Recovery:
		// If previous process crashed after fsync(auditFd) and before fsync(stateFd),
		// tailSeq == st.HWMSeq + 1 and tailPrevHash == st.HWMHash.
		if tailSeq == st.HWMSeq+1 && tailPrevHash == st.HWMHash {
			now := time.Now()
			catchupHWM := StateDBRecordV1{
				Version:   "mcp-authz-state/v1",
				LedgerID:  st.LedgerID,
				Kind:      "audit_hwm",
				GatewayID: l.pol.GatewayID,
				Key:       "hwm",
				AuditSeq:  tailSeq,
				AuditHash: tailHash,
				IssuedAt:  now.Unix(),
				ExpiresAt: 0,
			}
			hwmLine, err := FormatStateRecordLine(catchupHWM)
			if err != nil {
				return err
			}
			if _, err := stateFile.Write(hwmLine); err != nil {
				return NewError(ErrStateLedgerUnavailable, 0, "write catchup audit_hwm: %v", err)
			}
			if err := stateFile.Sync(); err != nil {
				return NewError(ErrStateLedgerUnavailable, 0, "fsync catchup audit_hwm: %v", err)
			}
			st.HWMSeq = tailSeq
			st.HWMHash = tailHash
			l.cachedSize += int64(len(hwmLine))
			l.cachedState = st.clone()

			// Append an audited hwm_recovered event
			return l.appendAuditAndHWMLocked(stateFile, auditFile, st, AuditRecordV1{
				Timestamp:       now.UTC().Format(time.RFC3339Nano),
				GatewayID:       l.pol.GatewayID,
				LedgerID:        st.LedgerID,
				ServerName:      l.pol.ServerName,
				ToolName:        "_system",
				ActionClass:     "system",
				Decision:        "hwm_recovered",
				Stage:           0,
				PrincipalID:     "_system",
				PrincipalSub:    "_system",
				EffectiveScopes: []string{},
				RedactedArgs:    map[string]any{},
			}, now)
		}
		return NewError(ErrAuditLogCorrupted, 0, "audit.jsonl tail (seq=%d, hash=%s) does not match state.db audit_hwm (seq=%d, hash=%s)", tailSeq, tailHash, st.HWMSeq, st.HWMHash)
	})
}

func verifyAuditChainFile(auditFile *os.File, expectedGatewayID, expectedLedgerID string) (uint64, string, string, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(auditFile.Fd()), &st); err != nil {
		return 0, "", "", NewError(ErrAuditLogCorrupted, 0, "fstat audit.jsonl: %v", err)
	}
	if st.Size == 0 {
		return 0, "", "", NewError(ErrAuditLogUninitialized, 0, "audit.jsonl is empty")
	}
	if st.Size > MaxLedgerFileBytes {
		return 0, "", "", NewError(ErrPayloadTooLarge, 0, "audit.jsonl size %d exceeds %d bytes", st.Size, MaxLedgerFileBytes)
	}
	data := make([]byte, st.Size)
	if _, err := auditFile.ReadAt(data, 0); err != nil && err != io.EOF {
		return 0, "", "", NewError(ErrAuditLogCorrupted, 0, "read audit.jsonl: %v", err)
	}
	if data[len(data)-1] != '\n' {
		return 0, "", "", NewError(ErrAuditLogCorrupted, 0, "audit.jsonl has incomplete final line (missing trailing newline)")
	}
	lines := bytes.Split(data[:len(data)-1], []byte{'\n'})
	expectedPrev := AuditGenesisZeros
	var lastSeq uint64
	var lastPrevHash string
	var lastHash string

	for i, line := range lines {
		expectedSeq := uint64(i + 1)
		rec, err := parseAndVerifyAuditLine(line, expectedSeq, expectedPrev, expectedGatewayID, expectedLedgerID)
		if err != nil {
			return 0, "", "", err
		}
		lastSeq = rec.Seq
		lastPrevHash = rec.PrevHash
		lastHash = rec.RecordHash
		expectedPrev = rec.RecordHash
	}
	return lastSeq, lastPrevHash, lastHash, nil
}

func parseAndVerifyAuditLine(line []byte, expectedSeq uint64, expectedPrevHash, expectedGatewayID, expectedLedgerID string) (AuditRecordV1, error) {
	var rec AuditRecordV1
	if _, err := DecodeStrictJSONWithCap(line, MaxConfigFileBytes, false); err != nil {
		return rec, NewError(ErrAuditLogCorrupted, 0, "audit.jsonl seq %d failed strict JSON decode: %v", expectedSeq, err)
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return rec, NewError(ErrAuditLogCorrupted, 0, "audit.jsonl seq %d decode failed: %v", expectedSeq, err)
	}
	if rec.Seq != expectedSeq {
		return rec, NewError(ErrAuditLogCorrupted, 0, "audit.jsonl sequence discontinuity: got %d, expected %d", rec.Seq, expectedSeq)
	}
	if rec.PrevHash != expectedPrevHash {
		return rec, NewError(ErrAuditLogCorrupted, 0, "audit.jsonl seq %d prev_hash mismatch", expectedSeq)
	}
	if expectedGatewayID != "" && rec.GatewayID != expectedGatewayID {
		return rec, NewError(ErrAuditLogCorrupted, 0, "audit.jsonl seq %d gateway_id %q != %q", expectedSeq, rec.GatewayID, expectedGatewayID)
	}
	if expectedLedgerID != "" && rec.LedgerID != expectedLedgerID {
		return rec, NewError(ErrAuditLogCorrupted, 0, "audit.jsonl seq %d ledger_id %q != %q", expectedSeq, rec.LedgerID, expectedLedgerID)
	}
	computedHash, err := ComputeAuditRecordHash(rec)
	if err != nil || rec.RecordHash != computedHash {
		return rec, NewError(ErrAuditLogCorrupted, 0, "audit.jsonl seq %d record_hash mismatch", expectedSeq)
	}
	jcsBytes, err := MarshalJCS(rec)
	if err != nil || !bytes.Equal(line, jcsBytes) {
		return rec, NewError(ErrAuditLogCorrupted, 0, "audit.jsonl seq %d is not JCS canonical", expectedSeq)
	}
	return rec, nil
}

// appendAuditAndHWMLocked appends an AuditRecordV1 (with seq = st.HWMSeq + 1, prev_hash = st.HWMHash)
// to auditFile + fsync, and then appends the updated audit_hwm record to stateFile + fsync.
func (l *Ledger) appendAuditAndHWMLocked(stateFile *os.File, auditFile *os.File, st *parsedLedgerState, rec AuditRecordV1, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	rec.Seq = st.HWMSeq + 1
	if rec.Timestamp == "" {
		rec.Timestamp = now.UTC().Format(time.RFC3339Nano)
	}
	rec.Timestamp = SanitizeSafeJSONString(rec.Timestamp)
	rec.GatewayID = SanitizeSafeJSONString(l.pol.GatewayID)
	rec.LedgerID = SanitizeSafeJSONString(st.LedgerID)
	rec.ServerName = SanitizeSafeJSONString(l.pol.ServerName)
	rec.ToolName = SanitizeSafeJSONString(rec.ToolName)
	rec.ActionClass = SanitizeSafeJSONString(rec.ActionClass)
	rec.Decision = SanitizeSafeJSONString(rec.Decision)
	rec.ErrorCode = SanitizeSafeJSONString(rec.ErrorCode)
	rec.PrincipalID = SanitizeSafeJSONString(rec.PrincipalID)
	rec.PrincipalSub = SanitizeSafeJSONString(rec.PrincipalSub)
	rec.PrincipalEmail = SanitizeSafeJSONString(rec.PrincipalEmail)
	rec.ApproverSub = SanitizeSafeJSONString(rec.ApproverSub)
	rec.ApprovalJTI = SanitizeSafeJSONString(rec.ApprovalJTI)
	rec.TicketID = SanitizeSafeJSONString(rec.TicketID)
	rec.IntentDigest = SanitizeSafeJSONString(rec.IntentDigest)
	if rec.EffectiveScopes == nil {
		rec.EffectiveScopes = []string{}
	} else {
		rec.EffectiveScopes = SanitizeSafeJSONValue(rec.EffectiveScopes).([]string)
	}
	if rec.RedactedArgs == nil {
		rec.RedactedArgs = map[string]any{}
	} else {
		rec.RedactedArgs = SanitizeSafeJSONValue(rec.RedactedArgs).(map[string]any)
	}
	rec.PrevHash = st.HWMHash

	hashHex, err := ComputeAuditRecordHash(rec)
	if err != nil {
		return NewError(ErrAuditLogUnavailable, 4, "compute audit hash: %v", err)
	}
	rec.RecordHash = hashHex
	auditLine, err := MarshalJCS(rec)
	if err != nil {
		return NewError(ErrAuditLogUnavailable, 4, "marshal audit record: %v", err)
	}
	auditLine = append(auditLine, '\n')
	if _, err := auditFile.Write(auditLine); err != nil {
		return NewError(ErrAuditLogUnavailable, 4, "append audit.jsonl: %v", err)
	}
	if err := auditFile.Sync(); err != nil {
		return NewError(ErrAuditLogUnavailable, 4, "fsync audit.jsonl: %v", err)
	}

	if l.SkipNextHWMUpdateForTest {
		l.SkipNextHWMUpdateForTest = false
		return nil
	}

	hwmRec := StateDBRecordV1{
		Version:   "mcp-authz-state/v1",
		LedgerID:  st.LedgerID,
		Kind:      "audit_hwm",
		GatewayID: l.pol.GatewayID,
		Key:       "hwm",
		AuditSeq:  rec.Seq,
		AuditHash: rec.RecordHash,
		IssuedAt:  now.Unix(),
		ExpiresAt: 0,
	}
	hwmLine, err := FormatStateRecordLine(hwmRec)
	if err != nil {
		return NewError(ErrStateLedgerUnavailable, 4, "format audit_hwm: %v", err)
	}
	if _, err := stateFile.Write(hwmLine); err != nil {
		return NewError(ErrStateLedgerUnavailable, 4, "append audit_hwm to state.db: %v", err)
	}
	if err := stateFile.Sync(); err != nil {
		return NewError(ErrStateLedgerUnavailable, 4, "fsync state.db: %v", err)
	}

	st.HWMSeq = rec.Seq
	st.HWMHash = rec.RecordHash
	l.cachedSize += int64(len(hwmLine))
	l.cachedState = st.clone()

	if l.cachedSize > MaxStateDBCompactionBytes {
		return l.compactLocked(st, now)
	}
	return nil
}

// AppendAudit appends a single audit record and updates audit_hwm inside the unified lock.
func (l *Ledger) AppendAudit(rec AuditRecordV1, now time.Time) error {
	return l.withExclusiveLock(func(stateFile *os.File, auditFile *os.File, st *parsedLedgerState) error {
		return l.appendAuditAndHWMLocked(stateFile, auditFile, st, rec, now)
	})
}

// RecordChallengeAndAudit checks `max_challenges_per_minute` for `principalIdentityID`,
// appends a `challenge` state record (or denies with `CHALLENGE_RATE_LIMIT_EXCEEDED`),
// and appends the corresponding audit record + `audit_hwm` in a single atomic lock acquisition.
func (l *Ledger) RecordChallengeAndAudit(principalIdentityID string, auditTemplate AuditRecordV1, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	nowUnix := now.Unix()
	maxCh := l.pol.AgentProfile.MaxChallengesPerMinute

	return l.withExclusiveLock(func(stateFile *os.File, auditFile *os.File, st *parsedLedgerState) error {
		recentChallenges := 0
		for _, ch := range st.Challenges {
			if ch.PrincipalID == principalIdentityID && ch.IssuedAt > nowUnix-60 && ch.ExpiresAt > nowUnix {
				recentChallenges++
			}
		}
		if maxCh > 0 && recentChallenges >= maxCh {
			denyAudit := auditTemplate
			denyAudit.Decision = "deny"
			denyAudit.Stage = 4
			denyAudit.ErrorCode = string(ErrChallengeRateLimitExceeded)
			_ = l.appendAuditAndHWMLocked(stateFile, auditFile, st, denyAudit, now)
			return NewError(ErrChallengeRateLimitExceeded, 4, "principal %q exceeded max_challenges_per_minute (%d)", principalIdentityID, maxCh)
		}

		chRec := StateDBRecordV1{
			Version:   "mcp-authz-state/v1",
			LedgerID:  st.LedgerID,
			Kind:      "challenge",
			GatewayID: l.pol.GatewayID,
			Key:       principalIdentityID,
			Count:     1,
			IssuedAt:  nowUnix,
			ExpiresAt: nowUnix + 60,
		}
		chLine, err := FormatStateRecordLine(chRec)
		if err != nil {
			return err
		}
		if _, err := stateFile.Write(chLine); err != nil {
			return NewError(ErrStateLedgerUnavailable, 4, "append challenge record: %v", err)
		}
		st.Challenges = append(st.Challenges, challengeEntry{
			PrincipalID: principalIdentityID,
			IssuedAt:    nowUnix,
			ExpiresAt:   nowUnix + 60,
		})
		l.cachedSize += int64(len(chLine))

		return l.appendAuditAndHWMLocked(stateFile, auditFile, st, auditTemplate, now)
	})
}

// CommitWriteAndPreForwardAudit executes Phase 2 of §4.4.3 inside a single `ledgerMu` + `flock` acquisition:
// 1. Verifies rolling write budgets (calls/min and targets/window) for `(ledger_id, principal_identity_id)`.
// 2. Verifies permanent SoD rules against freshly read `st.Grants`.
// 3. Verifies approval token `jti` anti-replay (if `write:high-risk`).
// 4. Appends `budget`, `grant` (if `sod_binding`), and `replay` (`jti`) records to `state.db`.
// 5. Appends `"pre_forward_allow"` to `audit.jsonl` + `fsync` and `audit_hwm` to `state.db` + `fsync`.
func (l *Ledger) CommitWriteAndPreForwardAudit(
	principalIdentityID string,
	targetCount int,
	sodSubjects []string,
	sodEntitlements []string,
	approvalClaims *ApprovalTokenClaimsV1,
	preForwardAudit AuditRecordV1,
	now time.Time,
) error {
	if now.IsZero() {
		now = time.Now()
	}
	nowUnix := now.Unix()
	windowSec := l.pol.AgentProfile.BudgetWindowSeconds
	if windowSec < 60 {
		windowSec = 3600
	}
	maxCallsPerMin := l.pol.AgentProfile.MaxWriteCallsPerMinute
	maxTargetsPerWin := l.pol.AgentProfile.MaxWriteTargetsPerWindow

	return l.withExclusiveLock(func(stateFile *os.File, auditFile *os.File, st *parsedLedgerState) error {
		// 1. Check approval token JTI replay first (if write:high-risk)
		if approvalClaims != nil {
			if existing, exists := st.Replays[approvalClaims.JTI]; exists && existing.ExpiresAt >= nowUnix {
				denyRec := preForwardAudit
				denyRec.Decision = "deny"
				denyRec.Stage = 4
				denyRec.ErrorCode = string(ErrApprovalTokenReplayed)
				_ = l.appendAuditAndHWMLocked(stateFile, auditFile, st, denyRec, now)
				return NewError(ErrApprovalTokenReplayed, 4, "approval token jti %q has already been consumed", approvalClaims.JTI)
			}
		}

		// 2. Re-verify permanent SoD under the exclusive lock
		if len(sodSubjects) > 0 && len(sodEntitlements) > 0 {
			if err := CheckSoDRules(l.pol, sodSubjects, sodEntitlements, st.Grants); err != nil {
				denyRec := preForwardAudit
				denyRec.Decision = "deny"
				denyRec.Stage = 3
				denyRec.ErrorCode = string(ErrSoDConflictDetected)
				_ = l.appendAuditAndHWMLocked(stateFile, auditFile, st, denyRec, now)
				return err
			}
		}

		// 3. Check rolling write budgets for principalIdentityID
		callsLastMin := 0
		targetsInWindow := 0
		for _, b := range st.Budgets {
			if b.PrincipalID != principalIdentityID || b.ExpiresAt <= nowUnix {
				continue
			}
			if b.IssuedAt > nowUnix-60 {
				callsLastMin++
			}
			if b.IssuedAt > nowUnix-windowSec {
				targetsInWindow += b.Count
			}
		}
		if (maxCallsPerMin > 0 && callsLastMin+1 > maxCallsPerMin) ||
			(maxTargetsPerWin > 0 && targetsInWindow+targetCount > maxTargetsPerWin) {
			denyRec := preForwardAudit
			denyRec.Decision = "deny"
			denyRec.Stage = 4
			denyRec.ErrorCode = string(ErrPrincipalWriteBudgetExhausted)
			_ = l.appendAuditAndHWMLocked(stateFile, auditFile, st, denyRec, now)
			return NewError(ErrPrincipalWriteBudgetExhausted, 4, "principal %q exhausted write budget (calls/min=%d/%d, targets/win=%d+%d/%d)",
				principalIdentityID, callsLastMin, maxCallsPerMin, targetsInWindow, targetCount, maxTargetsPerWin)
		}

		// 4. Build and append state records (`budget`, `grant`, `replay`)
		var stateBuf bytes.Buffer

		budgetRec := StateDBRecordV1{
			Version:   "mcp-authz-state/v1",
			LedgerID:  st.LedgerID,
			Kind:      "budget",
			GatewayID: l.pol.GatewayID,
			Key:       principalIdentityID,
			Count:     targetCount,
			IssuedAt:  nowUnix,
			ExpiresAt: nowUnix + windowSec,
		}
		bLine, err := FormatStateRecordLine(budgetRec)
		if err != nil {
			return err
		}
		stateBuf.Write(bLine)

		for _, subj := range sodSubjects {
			for _, ent := range sodEntitlements {
				grantRec := StateDBRecordV1{
					Version:   "mcp-authz-state/v1",
					LedgerID:  st.LedgerID,
					Kind:      "grant",
					GatewayID: l.pol.GatewayID,
					Key:       subj,
					SubKey:    ent,
					IssuedAt:  nowUnix,
					ExpiresAt: 0, // Permanent across compactions until revoked via revoke-grant
				}
				gLine, err := FormatStateRecordLine(grantRec)
				if err != nil {
					return err
				}
				stateBuf.Write(gLine)
			}
		}

		if approvalClaims != nil {
			skew := l.pol.PrincipalAuth.MaxClockSkewSeconds
			if skew <= 0 {
				skew = 30
			}
			replayRec := StateDBRecordV1{
				Version:   "mcp-authz-state/v1",
				LedgerID:  st.LedgerID,
				Kind:      "replay",
				GatewayID: l.pol.GatewayID,
				Key:       approvalClaims.JTI,
				Value:     approvalClaims.IntentDigest,
				IssuedAt:  nowUnix,
				ExpiresAt: approvalClaims.ExpiresAt + skew + 60,
			}
			rLine, err := FormatStateRecordLine(replayRec)
			if err != nil {
				return err
			}
			stateBuf.Write(rLine)
		}

		if _, err := stateFile.Write(stateBuf.Bytes()); err != nil {
			return NewError(ErrStateLedgerUnavailable, 4, "append write state records: %v", err)
		}
		if err := stateFile.Sync(); err != nil {
			return NewError(ErrStateLedgerUnavailable, 4, "fsync state.db: %v", err)
		}

		// Update in-memory state
		st.Budgets = append(st.Budgets, budgetEntry{
			PrincipalID: principalIdentityID,
			Count:       targetCount,
			IssuedAt:    nowUnix,
			ExpiresAt:   nowUnix + windowSec,
		})
		for _, subj := range sodSubjects {
			if st.Grants[subj] == nil {
				st.Grants[subj] = make(map[string]struct{})
				st.GrantOrigin[subj] = make(map[string]int64)
			}
			for _, ent := range sodEntitlements {
				st.Grants[subj][ent] = struct{}{}
				st.GrantOrigin[subj][ent] = nowUnix
			}
		}
		if approvalClaims != nil {
			skew := l.pol.PrincipalAuth.MaxClockSkewSeconds
			if skew <= 0 {
				skew = 30
			}
			st.Replays[approvalClaims.JTI] = StateDBRecordV1{
				Version:   "mcp-authz-state/v1",
				LedgerID:  st.LedgerID,
				Kind:      "replay",
				GatewayID: l.pol.GatewayID,
				Key:       approvalClaims.JTI,
				Value:     approvalClaims.IntentDigest,
				IssuedAt:  nowUnix,
				ExpiresAt: approvalClaims.ExpiresAt + skew + 60,
			}
		}
		l.cachedSize += int64(stateBuf.Len())
		l.cachedState = st.clone()

		// 5. Append pre_forward_allow audit record + audit_hwm
		return l.appendAuditAndHWMLocked(stateFile, auditFile, st, preForwardAudit, now)
	})
}

// ForceCompact triggers an atomic in-lock compaction of state.db (`state.db.tmp` -> `os.Rename`).
func (l *Ledger) ForceCompact(now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	return l.withExclusiveLock(func(_ *os.File, _ *os.File, st *parsedLedgerState) error {
		return l.compactLocked(st, now)
	})
}

func (l *Ledger) compactLocked(st *parsedLedgerState, now time.Time) error {
	nowUnix := now.Unix()
	var buf bytes.Buffer

	// 1. Genesis header record
	hdrLine, err := FormatStateRecordLine(StateDBRecordV1{
		Version:   "mcp-authz-state/v1",
		LedgerID:  st.LedgerID,
		Kind:      "header",
		GatewayID: l.pol.GatewayID,
		Key:       "ledger_id",
		Value:     st.LedgerID,
		IssuedAt:  nowUnix,
		ExpiresAt: 0,
	})
	if err != nil {
		return err
	}
	buf.Write(hdrLine)

	// 2. Non-expired replay records (sorted by JTI)
	jtiKeys := make([]string, 0, len(st.Replays))
	for jti, r := range st.Replays {
		if r.ExpiresAt > nowUnix {
			jtiKeys = append(jtiKeys, jti)
		}
	}
	slices.Sort(jtiKeys)
	keptReplays := make(map[string]StateDBRecordV1, len(jtiKeys))
	for _, jti := range jtiKeys {
		r := st.Replays[jti]
		keptReplays[jti] = r
		line, err := FormatStateRecordLine(r)
		if err != nil {
			return err
		}
		buf.Write(line)
	}

	// 3. Non-expired budget records
	var keptBudgets []budgetEntry
	for _, b := range st.Budgets {
		if b.ExpiresAt > nowUnix {
			keptBudgets = append(keptBudgets, b)
			line, err := FormatStateRecordLine(StateDBRecordV1{
				Version:   "mcp-authz-state/v1",
				LedgerID:  st.LedgerID,
				Kind:      "budget",
				GatewayID: l.pol.GatewayID,
				Key:       b.PrincipalID,
				Count:     b.Count,
				IssuedAt:  b.IssuedAt,
				ExpiresAt: b.ExpiresAt,
			})
			if err != nil {
				return err
			}
			buf.Write(line)
		}
	}

	// 4. Non-expired challenge records
	var keptChallenges []challengeEntry
	for _, c := range st.Challenges {
		if c.ExpiresAt > nowUnix {
			keptChallenges = append(keptChallenges, c)
			line, err := FormatStateRecordLine(StateDBRecordV1{
				Version:   "mcp-authz-state/v1",
				LedgerID:  st.LedgerID,
				Kind:      "challenge",
				GatewayID: l.pol.GatewayID,
				Key:       c.PrincipalID,
				Count:     1,
				IssuedAt:  c.IssuedAt,
				ExpiresAt: c.ExpiresAt,
			})
			if err != nil {
				return err
			}
			buf.Write(line)
		}
	}

	// 5. All permanent SoD grant records (sorted deterministically)
	subjKeys := make([]string, 0, len(st.Grants))
	for subj := range st.Grants {
		subjKeys = append(subjKeys, subj)
	}
	slices.Sort(subjKeys)
	for _, subj := range subjKeys {
		entSet := st.Grants[subj]
		entKeys := make([]string, 0, len(entSet))
		for e := range entSet {
			entKeys = append(entKeys, e)
		}
		slices.Sort(entKeys)
		for _, e := range entKeys {
			iat := st.GrantOrigin[subj][e]
			if iat == 0 {
				iat = nowUnix
			}
			line, err := FormatStateRecordLine(StateDBRecordV1{
				Version:   "mcp-authz-state/v1",
				LedgerID:  st.LedgerID,
				Kind:      "grant",
				GatewayID: l.pol.GatewayID,
				Key:       subj,
				SubKey:    e,
				IssuedAt:  iat,
				ExpiresAt: 0,
			})
			if err != nil {
				return err
			}
			buf.Write(line)
		}
	}

	// 6. Current audit_hwm record
	hwmLine, err := FormatStateRecordLine(StateDBRecordV1{
		Version:   "mcp-authz-state/v1",
		LedgerID:  st.LedgerID,
		Kind:      "audit_hwm",
		GatewayID: l.pol.GatewayID,
		Key:       "hwm",
		AuditSeq:  st.HWMSeq,
		AuditHash: st.HWMHash,
		IssuedAt:  nowUnix,
		ExpiresAt: 0,
	})
	if err != nil {
		return err
	}
	buf.Write(hwmLine)

	tmpPath := l.pol.TCB.StateDBPath + ".tmp"
	_ = os.Remove(tmpPath)
	tmpFile, _, err := OpenVerifiedFile(tmpPath, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY, 0o600, AllowedServiceUIDs(l.pol), 0o177)
	if err != nil {
		return NewError(ErrStateLedgerUnavailable, 4, "open state.db.tmp for compaction: %v", err)
	}
	if _, err := tmpFile.Write(buf.Bytes()); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return NewError(ErrStateLedgerUnavailable, 4, "write state.db.tmp: %v", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return NewError(ErrStateLedgerUnavailable, 4, "fsync state.db.tmp: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return NewError(ErrStateLedgerUnavailable, 4, "close state.db.tmp: %v", err)
	}
	if err := os.Rename(tmpPath, l.pol.TCB.StateDBPath); err != nil {
		_ = os.Remove(tmpPath)
		return NewError(ErrStateLedgerUnavailable, 4, "rename state.db.tmp -> state.db: %v", err)
	}
	_ = FsyncDir(filepath.Dir(l.pol.TCB.StateDBPath))

	// Re-stat the newly renamed state.db to update (cachedDev, cachedIno, cachedSize)
	newFile, newStat, err := OpenVerifiedFile(l.pol.TCB.StateDBPath, syscall.O_RDONLY, 0, AllowedServiceUIDs(l.pol), 0o177)
	if err != nil {
		return err
	}
	_ = newFile.Close()

	st.Replays = keptReplays
	st.Budgets = keptBudgets
	st.Challenges = keptChallenges
	l.cachedDev = uint64(newStat.Dev)
	l.cachedIno = uint64(newStat.Ino)
	l.cachedSize = newStat.Size
	l.cachedState = st.clone()
	return nil
}

// VerifyAuditCLI implements `mcp-authz-gateway verify-audit` (§3.5).
func VerifyAuditCLI(pol *PolicyV1) (uint64, string, error) {
	serviceUIDs := AllowedServiceUIDs(pol)
	lockPath := pol.TCB.StateDBPath + ".lock"
	lockFile, _, err := OpenVerifiedFile(lockPath, syscall.O_RDWR, 0, serviceUIDs, 0o177)
	if err != nil {
		return 0, "", NewError(ErrStateLedgerUninitialized, 0, "open %q: %v", lockPath, err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return 0, "", NewError(ErrStateLedgerUnavailable, 0, "flock: %v", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	stateBytes, err := ReadVerifiedFile(pol.TCB.StateDBPath, serviceUIDs, 0o177, MaxStateDBCompactionBytes*4)
	if err != nil {
		return 0, "", err
	}
	st := newParsedLedgerState()
	if err := applyStateRecordsBytes(st, stateBytes, pol.GatewayID, true); err != nil {
		return 0, "", err
	}

	auditFile, _, err := OpenVerifiedFile(pol.TCB.AuditLogPath, syscall.O_RDONLY, 0, serviceUIDs, 0o177)
	if err != nil {
		return 0, "", err
	}
	defer auditFile.Close()

	tailSeq, _, tailHash, err := verifyAuditChainFile(auditFile, pol.GatewayID, st.LedgerID)
	if err != nil {
		return 0, "", err
	}
	if tailSeq != st.HWMSeq || tailHash != st.HWMHash {
		return 0, "", NewError(ErrAuditLogCorrupted, 0, "audit.jsonl tail (seq=%d, hash=%s) != state.db audit_hwm (seq=%d, hash=%s)", tailSeq, tailHash, st.HWMSeq, st.HWMHash)
	}
	return tailSeq, tailHash, nil
}

// RepairLedgerCLI implements `mcp-authz-gateway repair` (§3.6):
// truncates an incomplete or torn final line on state.db and/or audit.jsonl (while refusing if any non-final
// line 1..N-1 is corrupted), reconciles a 1-record audit_hwm lag, and appends an audited `ledger_repaired` event.
func RepairLedgerCLI(pol *PolicyV1, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	serviceUIDs := AllowedServiceUIDs(pol)
	lockPath := pol.TCB.StateDBPath + ".lock"
	lockFile, _, err := OpenVerifiedFile(lockPath, syscall.O_RDWR, 0, serviceUIDs, 0o177)
	if err != nil {
		return NewError(ErrStateLedgerUninitialized, 0, "open %q: %v", lockPath, err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return NewError(ErrStateLedgerUnavailable, 0, "flock: %v", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	// 1. Inspect and repair state.db if its final line is torn
	stateFile, stateStat, err := OpenVerifiedFile(pol.TCB.StateDBPath, syscall.O_RDWR, 0, serviceUIDs, 0o177)
	if err != nil {
		return err
	}
	defer stateFile.Close()
	if stateStat.Size > MaxLedgerFileBytes {
		return NewError(ErrPayloadTooLarge, 0, "state.db size %d exceeds %d bytes", stateStat.Size, MaxLedgerFileBytes)
	}

	stateBytes := make([]byte, stateStat.Size)
	if _, err := stateFile.ReadAt(stateBytes, 0); err != nil && err != io.EOF {
		return NewError(ErrStateLedgerUnavailable, 0, "read state.db: %v", err)
	}
	validStateBytes, stateTruncated, err := validateOrTruncateFinalStateLine(stateBytes, pol.GatewayID)
	if err != nil {
		return err
	}
	if stateTruncated {
		if err := stateFile.Truncate(int64(len(validStateBytes))); err != nil {
			return NewError(ErrStateLedgerUnavailable, 0, "truncate state.db: %v", err)
		}
		if err := stateFile.Sync(); err != nil {
			return NewError(ErrStateLedgerUnavailable, 0, "fsync state.db: %v", err)
		}
	}
	st := newParsedLedgerState()
	if err := applyStateRecordsBytes(st, validStateBytes, pol.GatewayID, true); err != nil {
		return err
	}

	// 2. Inspect and repair audit.jsonl if its final line is torn
	auditFile, auditStat, err := OpenVerifiedFile(pol.TCB.AuditLogPath, syscall.O_RDWR, 0, serviceUIDs, 0o177)
	if err != nil {
		return err
	}
	defer auditFile.Close()
	if auditStat.Size > MaxLedgerFileBytes {
		return NewError(ErrPayloadTooLarge, 0, "audit.jsonl size %d exceeds %d bytes", auditStat.Size, MaxLedgerFileBytes)
	}

	auditBytes := make([]byte, auditStat.Size)
	if _, err := auditFile.ReadAt(auditBytes, 0); err != nil && err != io.EOF {
		return NewError(ErrAuditLogCorrupted, 0, "read audit.jsonl: %v", err)
	}
	validAuditBytes, auditTruncated, tailSeq, tailPrevHash, tailHash, err := validateOrTruncateFinalAuditLine(auditBytes, pol.GatewayID, st.LedgerID)
	if err != nil {
		return err
	}
	if auditTruncated {
		if err := auditFile.Truncate(int64(len(validAuditBytes))); err != nil {
			return NewError(ErrAuditLogCorrupted, 0, "truncate audit.jsonl: %v", err)
		}
		if err := auditFile.Sync(); err != nil {
			return NewError(ErrAuditLogCorrupted, 0, "fsync audit.jsonl: %v", err)
		}
	}

	// Verify HWM relationship (either equal or tail == hwm + 1)
	if tailSeq == st.HWMSeq+1 && tailPrevHash == st.HWMHash {
		st.HWMSeq = tailSeq
		st.HWMHash = tailHash
	} else if tailSeq != st.HWMSeq || tailHash != st.HWMHash {
		return NewError(ErrAuditLogCorrupted, 0, "cannot repair: audit tail seq=%d does not match audit_hwm seq=%d", tailSeq, st.HWMSeq)
	}

	// Seek to end and append ledger_repaired audit record + updated audit_hwm
	if _, err := stateFile.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	if _, err := auditFile.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	tmpLedger := &Ledger{pol: pol}
	return tmpLedger.appendAuditAndHWMLocked(stateFile, auditFile, st, AuditRecordV1{
		Timestamp:       now.UTC().Format(time.RFC3339Nano),
		GatewayID:       pol.GatewayID,
		LedgerID:        st.LedgerID,
		ServerName:      pol.ServerName,
		ToolName:        "_system",
		ActionClass:     "system",
		Decision:        "ledger_repaired",
		Stage:           0,
		PrincipalID:     "_system",
		PrincipalSub:    "_system",
		EffectiveScopes: []string{},
		RedactedArgs: map[string]any{
			"state_truncated": stateTruncated,
			"audit_truncated": auditTruncated,
		},
	}, now)
}

func validateOrTruncateFinalStateLine(data []byte, expectedGatewayID string) ([]byte, bool, error) {
	if len(data) == 0 {
		return nil, false, NewError(ErrStateLedgerUninitialized, 0, "state.db is empty")
	}
	hasTrailingNewline := data[len(data)-1] == '\n'
	trimmed := data
	if hasTrailingNewline {
		trimmed = data[:len(data)-1]
	}
	rawLines := bytes.Split(trimmed, []byte{'\n'})
	offset := 0
	for i, line := range rawLines {
		isLast := i == len(rawLines)-1
		if isLast && !hasTrailingNewline {
			if i == 0 {
				return nil, false, NewError(ErrStateLedgerUnavailable, 0, "state.db has no complete lines")
			}
			return data[:offset], true, nil
		}
		_, err := parseAndVerifyStateRecordLine(line)
		if err != nil {
			if isLast && i > 0 {
				return data[:offset], true, nil
			}
			return nil, false, err
		}
		offset += len(line) + 1
	}
	// Verify full semantic state on the retained bytes
	st := newParsedLedgerState()
	if err := applyStateRecordsBytes(st, data[:offset], expectedGatewayID, true); err != nil {
		return nil, false, err
	}
	return data[:offset], false, nil
}

func validateOrTruncateFinalAuditLine(data []byte, expectedGatewayID, expectedLedgerID string) ([]byte, bool, uint64, string, string, error) {
	if len(data) == 0 {
		return nil, false, 0, "", "", NewError(ErrAuditLogUninitialized, 0, "audit.jsonl is empty")
	}
	hasTrailingNewline := data[len(data)-1] == '\n'
	trimmed := data
	if hasTrailingNewline {
		trimmed = data[:len(data)-1]
	}
	rawLines := bytes.Split(trimmed, []byte{'\n'})
	offset := 0
	expectedPrev := AuditGenesisZeros
	var lastSeq uint64
	var lastPrevHash string
	var lastHash string

	for i, line := range rawLines {
		isLast := i == len(rawLines)-1
		expectedSeq := uint64(i + 1)
		if isLast && !hasTrailingNewline {
			if i == 0 {
				return nil, false, 0, "", "", NewError(ErrAuditLogCorrupted, 0, "audit.jsonl has no complete lines")
			}
			return data[:offset], true, lastSeq, lastPrevHash, lastHash, nil
		}
		rec, err := parseAndVerifyAuditLine(line, expectedSeq, expectedPrev, expectedGatewayID, expectedLedgerID)
		if err != nil {
			if isLast && i > 0 {
				return data[:offset], true, lastSeq, lastPrevHash, lastHash, nil
			}
			return nil, false, 0, "", "", err
		}
		lastSeq = rec.Seq
		lastPrevHash = rec.PrevHash
		lastHash = rec.RecordHash
		expectedPrev = rec.RecordHash
		offset += len(line) + 1
	}
	return data[:offset], false, lastSeq, lastPrevHash, lastHash, nil
}

// RevokeGrantCLI implements `mcp-authz-gateway revoke-grant` (§3.6):
// appends a permanent `grant_revoke` record to `state.db` and an audited `grant_revoked` record to `audit.jsonl`.
func RevokeGrantCLI(pol *PolicyV1, subject, entitlement, operator, ticketID string, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	for _, field := range []struct {
		name string
		val  string
	}{
		{"subject", subject},
		{"entitlement", entitlement},
		{"operator", operator},
		{"ticket", ticketID},
	} {
		if err := ValidateSafeJSONString(field.val); err != nil {
			return err
		}
		if strings.ContainsAny(field.val, "\r\n\t") {
			return NewError(ErrInvalidControlChar, 0, "--%s cannot contain newline or tab characters", field.name)
		}
	}
	subject = strings.TrimSpace(subject)
	entitlement = strings.TrimSpace(entitlement)
	operator = strings.TrimSpace(operator)
	ticketID = strings.TrimSpace(ticketID)
	if subject == "" || entitlement == "" || operator == "" || ticketID == "" {
		return NewError(ErrArgumentConstraintViolated, 0, "--subject, --entitlement, --operator, and --ticket are required for revoke-grant")
	}
	if pol.CompiledTicketRegex != nil && !pol.CompiledTicketRegex.MatchString(ticketID) {
		return NewError(ErrArgumentConstraintViolated, 0, "ticket %q does not match step_up.ticket_regex", ticketID)
	}

	l, err := OpenLedger(pol)
	if err != nil {
		return err
	}
	defer l.Close()

	return l.withExclusiveLock(func(stateFile *os.File, auditFile *os.File, st *parsedLedgerState) error {
		revRec := StateDBRecordV1{
			Version:   "mcp-authz-state/v1",
			LedgerID:  st.LedgerID,
			Kind:      "grant_revoke",
			GatewayID: pol.GatewayID,
			Key:       subject,
			SubKey:    entitlement,
			Value:     operator + ":" + ticketID,
			IssuedAt:  now.Unix(),
			ExpiresAt: 0,
		}
		revLine, err := FormatStateRecordLine(revRec)
		if err != nil {
			return err
		}
		if _, err := stateFile.Write(revLine); err != nil {
			return NewError(ErrStateLedgerUnavailable, 0, "append grant_revoke: %v", err)
		}
		if st.Grants[subject] != nil {
			delete(st.Grants[subject], entitlement)
			delete(st.GrantOrigin[subject], entitlement)
		}
		l.cachedSize += int64(len(revLine))
		l.cachedState = st.clone()

		return l.appendAuditAndHWMLocked(stateFile, auditFile, st, AuditRecordV1{
			Timestamp:       now.UTC().Format(time.RFC3339Nano),
			GatewayID:       pol.GatewayID,
			LedgerID:        st.LedgerID,
			ServerName:      pol.ServerName,
			ToolName:        "_revoke_grant",
			ActionClass:     "system",
			Decision:        "grant_revoked",
			Stage:           0,
			PrincipalID:     operator,
			PrincipalSub:    operator,
			TicketID:        ticketID,
			EffectiveScopes: []string{},
			RedactedArgs: map[string]any{
				"subject":     subject,
				"entitlement": entitlement,
				"operator":    operator,
				"ticket_id":   ticketID,
			},
		}, now)
	})
}
