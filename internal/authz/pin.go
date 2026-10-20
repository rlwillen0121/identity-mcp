//go:build unix

package authz

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const MaxUpstreamTools = 250

// CanonicalToolSurfaceV1 is the JCS-canonicalized representation of an upstream MCP tool (§4.1.2).
type CanonicalToolSurfaceV1 struct {
	Name            string         `json:"name"`
	Title           string         `json:"title"`
	Description     string         `json:"description"`
	InputSchema     map[string]any `json:"inputSchema"`
	OutputSchema    map[string]any `json:"outputSchema"`
	ReadOnlyHint    bool           `json:"read_only_hint"`
	DestructiveHint bool           `json:"destructive_hint"`
	IdempotentHint  bool           `json:"idempotent_hint"`
	OpenWorldHint   bool           `json:"open_world_hint"`
}

// PinnedToolEntryV1 stores a tool's canonical surface alongside its SHA-256 JCS digest.
type PinnedToolEntryV1 struct {
	Name            string         `json:"name"`
	Title           string         `json:"title"`
	Description     string         `json:"description"`
	InputSchema     map[string]any `json:"inputSchema"`
	OutputSchema    map[string]any `json:"outputSchema"`
	ReadOnlyHint    bool           `json:"read_only_hint"`
	DestructiveHint bool           `json:"destructive_hint"`
	IdempotentHint  bool           `json:"idempotent_hint"`
	OpenWorldHint   bool           `json:"open_world_hint"`
	ToolSHA256      string         `json:"tool_sha256"`
}

// Surface extracts CanonicalToolSurfaceV1 from a PinnedToolEntryV1.
func (p *PinnedToolEntryV1) Surface() CanonicalToolSurfaceV1 {
	return CanonicalToolSurfaceV1{
		Name:            p.Name,
		Title:           p.Title,
		Description:     p.Description,
		InputSchema:     p.InputSchema,
		OutputSchema:    p.OutputSchema,
		ReadOnlyHint:    p.ReadOnlyHint,
		DestructiveHint: p.DestructiveHint,
		IdempotentHint:  p.IdempotentHint,
		OpenWorldHint:   p.OpenWorldHint,
	}
}

// ManifestLockfileV1 is the on-disk schema of `mcp-authz.lock.json`.
type ManifestLockfileV1 struct {
	SchemaVersion        string                        `json:"schema_version"`
	ServerName           string                        `json:"server_name"`
	UpstreamBinarySHA256 string                        `json:"upstream_binary_sha256"`
	Tools                map[string]*PinnedToolEntryV1 `json:"tools"`
}

// ComputeToolSurfaceHash computes `hex(SHA256(JCS(CanonicalToolSurfaceV1)))`.
func ComputeToolSurfaceHash(surface CanonicalToolSurfaceV1) (string, error) {
	jcsBytes, err := MarshalJCS(surface)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(jcsBytes)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyUpstreamBinary opens commandPath via OpenVerifiedFile, verifies that it begins with a valid
// ELF or Mach-O binary header (rejecting `#!` script interpreters with UPSTREAM_SCRIPT_INTERPRETER_FORBIDDEN),
// computes its SHA-256 digest, and compares against expectedSHA256 if non-empty.
func VerifyUpstreamBinary(commandPath string, expectedSHA256 string) (*os.File, string, error) {
	f, st, err := OpenVerifiedFile(commandPath, syscall.O_RDONLY, 0, []uint32{0, uint32(os.Geteuid())}, 0o022)
	if err != nil {
		return nil, "", err
	}
	if st.Size < 4 {
		_ = f.Close()
		return nil, "", NewError(ErrUpstreamScriptForbidden, 0, "upstream binary %q is smaller than 4 bytes", commandPath)
	}

	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		_ = f.Close()
		return nil, "", NewError(ErrManifestPinMismatch, 0, "read magic header from %q: %v", commandPath, err)
	}
	if magic[0] == '#' && magic[1] == '!' {
		_ = f.Close()
		return nil, "", NewError(ErrUpstreamScriptForbidden, 0, "upstream command %q is a #! script interpreter (compiled ELF/Mach-O required)", commandPath)
	}
	if !isELForMachOMagic(magic) {
		_ = f.Close()
		return nil, "", NewError(ErrUpstreamScriptForbidden, 0, "upstream command %q does not have an ELF or Mach-O binary header", commandPath)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		_ = f.Close()
		return nil, "", NewError(ErrManifestPinMismatch, 0, "hash upstream binary %q: %v", commandPath, err)
	}
	actualHex := hex.EncodeToString(h.Sum(nil))
	if expectedSHA256 != "" && actualHex != asciiLower(expectedSHA256) {
		_ = f.Close()
		return nil, "", NewError(ErrManifestPinMismatch, 0, "upstream binary %q SHA-256 %s != pinned %s", commandPath, actualHex, expectedSHA256)
	}
	return f, actualHex, nil
}

func isELForMachOMagic(m [4]byte) bool {
	// ELF: 0x7F 'E' 'L' 'F'
	if m[0] == 0x7f && m[1] == 'E' && m[2] == 'L' && m[3] == 'F' {
		return true
	}
	// Mach-O 32/64 big/little endian & universal fat binary
	switch {
	case m[0] == 0xfe && m[1] == 0xed && m[2] == 0xfa && (m[3] == 0xce || m[3] == 0xcf):
		return true
	case (m[0] == 0xce || m[0] == 0xcf) && m[1] == 0xfa && m[2] == 0xed && m[3] == 0xfe:
		return true
	case m[0] == 0xca && m[1] == 0xfe && m[2] == 0xba && m[3] == 0xbe:
		return true
	default:
		return false
	}
}

// LoadLockfile reads and validates `mcp-authz.lock.json` via OpenVerifiedFile.
func LoadLockfile(lockfilePath string, expectedUIDs []uint32) (*ManifestLockfileV1, []byte, error) {
	rawBytes, err := ReadVerifiedFile(lockfilePath, expectedUIDs, 0o022, MaxConfigFileBytes)
	if err != nil {
		return nil, nil, NewError(ErrManifestPinMismatch, 0, "cannot read lockfile %q: %v", lockfilePath, err)
	}
	if _, err := DecodeStrictJSONWithCap(rawBytes, MaxConfigFileBytes, false); err != nil {
		return nil, nil, NewError(ErrManifestPinMismatch, 0, "lockfile %q failed strict JSON decode: %v", lockfilePath, err)
	}
	var lf ManifestLockfileV1
	dec := json.NewDecoder(bytes.NewReader(rawBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&lf); err != nil {
		return nil, nil, NewError(ErrManifestPinMismatch, 0, "decode lockfile %q: %v", lockfilePath, err)
	}
	if lf.SchemaVersion != "mcp-authz-lockfile/v1" {
		return nil, nil, NewError(ErrManifestPinMismatch, 0, "unsupported lockfile schema_version %q", lf.SchemaVersion)
	}
	for tName, entry := range lf.Tools {
		if entry == nil || entry.Name != tName {
			return nil, nil, NewError(ErrManifestPinMismatch, 0, "lockfile tool entry %q malformed", tName)
		}
		computed, err := ComputeToolSurfaceHash(entry.Surface())
		if err != nil || computed != entry.ToolSHA256 {
			return nil, nil, NewError(ErrManifestPinMismatch, 0, "lockfile tool %q tool_sha256 mismatch (got %q, expected %q)", tName, entry.ToolSHA256, computed)
		}
	}
	return &lf, rawBytes, nil
}

// UpstreamHandle wraps a running upstream MCP server subprocess or an in-memory test transport session.
type UpstreamHandle struct {
	Session      *mcp.ClientSession
	SecretValues map[string]string
	BinarySHA256 string
	cmd          *exec.Cmd
	stdinCloser  io.Closer
	stdoutCloser io.Closer
	closeOnce    sync.Once
}

// Close terminates the upstream ClientSession and kills the child subprocess if one was spawned.
func (u *UpstreamHandle) Close() {
	if u == nil {
		return
	}
	u.closeOnce.Do(func() {
		if u.Session != nil {
			_ = u.Session.Close()
		}
		if u.stdinCloser != nil {
			_ = u.stdinCloser.Close()
		}
		if u.stdoutCloser != nil {
			_ = u.stdoutCloser.Close()
		}
		if u.cmd != nil && u.cmd.Process != nil {
			_ = u.cmd.Process.Kill()
			_, _ = u.cmd.Process.Wait()
		}
	})
}

// NewUpstreamClientWithCacheBypass constructs an `mcp.Client` with a sending middleware that forces
// `ListToolsResult.TTLMs = 0` on every `tools/list` response so `go-sdk` `toolsCache` never serves stale manifests (§4.1.2).
func NewUpstreamClientWithCacheBypass(onToolsChanged func(context.Context, *mcp.ToolListChangedRequest)) *mcp.Client {
	client := mcp.NewClient(
		&mcp.Implementation{Name: "mcp-authz-gateway-client", Version: "0.1.0"},
		&mcp.ClientOptions{
			ToolListChangedHandler: onToolsChanged,
		},
	)
	client.AddSendingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if err == nil && method == "tools/list" {
				if ltRes, ok := res.(*mcp.ListToolsResult); ok && ltRes != nil {
					ltRes.TTLMs = 0
				}
			}
			return res, err
		}
	})
	return client
}

// StartUpstreamSubprocess verifies the upstream binary, scrubs the child environment, launches
// the subprocess without `exec.LookPath`, and connects over `mcp.IOTransport` with `MaxLineLength`.
func StartUpstreamSubprocess(
	ctx context.Context,
	pol *PolicyV1,
	expectedBinarySHA string,
	extraRedactSecrets []string,
	onToolsChanged func(context.Context, *mcp.ToolListChangedRequest),
	onProcessExit func(),
) (*UpstreamHandle, error) {
	binFile, actualSHA, err := VerifyUpstreamBinary(pol.Upstream.Command, expectedBinarySHA)
	if err != nil {
		return nil, err
	}
	defer func() {
		if binFile != nil {
			_ = binFile.Close()
		}
	}()

	childEnv, secretValues, err := BuildChildEnv(pol)
	if err != nil {
		return nil, err
	}
	execPath, err := execPathForVerifiedFD(int(binFile.Fd()), pol.Upstream.Command)
	if err != nil {
		return nil, err
	}

	cmd := &exec.Cmd{
		Path: execPath,
		Args: append([]string{pol.Upstream.Command}, pol.Upstream.Args...),
		Env:  childEnv,
	}
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, NewError(ErrUpstreamProcessTerminated, 0, "stdin pipe: %v", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, NewError(ErrUpstreamProcessTerminated, 0, "stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, NewError(ErrUpstreamProcessTerminated, 0, "stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, NewError(ErrUpstreamProcessTerminated, 0, "start upstream %q: %v", pol.Upstream.Command, err)
	}
	// Close verified fd in parent now that execve has started
	_ = binFile.Close()
	binFile = nil

	scanner := NewSecretScanner(secretValues, extraRedactSecrets...)
	go drainAndRedactChildStderr(stderrPipe, scanner, onProcessExit)

	maxLine := pol.Upstream.MaxOutputBytes + 65536
	if maxLine < 131072 {
		maxLine = 131072
	}
	transport := &mcp.IOTransport{
		Reader:        stdoutPipe,
		Writer:        stdinPipe,
		MaxLineLength: maxLine,
	}

	client := NewUpstreamClientWithCacheBypass(onToolsChanged)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		_ = stdinPipe.Close()
		_ = stdoutPipe.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		return nil, NewError(ErrUpstreamProcessTerminated, 0, "connect upstream MCP session: %v", err)
	}

	return &UpstreamHandle{
		Session:      session,
		SecretValues: secretValues,
		BinarySHA256: actualSHA,
		cmd:          cmd,
		stdinCloser:  stdinPipe,
		stdoutCloser: stdoutPipe,
	}, nil
}

// drainAndRedactChildStderr implements the 32 KiB sliding-window secret scrubber over child stderr (§4.6.1).
func drainAndRedactChildStderr(r io.ReadCloser, sc *SecretScanner, onExit func()) {
	defer func() {
		_ = r.Close()
		if onExit != nil {
			onExit()
		}
	}()
	const windowSize = 32768
	buf := make([]byte, 4096)
	var window []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			window = append(window, buf[:n]...)
			redacted := sc.RedactString(string(window))
			window = []byte(redacted)
			if len(window) > windowSize {
				flushLen := len(window) - (windowSize / 2)
				_, _ = os.Stderr.Write(window[:flushLen])
				window = window[flushLen:]
			}
		}
		if err != nil {
			if len(window) > 0 {
				redacted := sc.RedactString(string(window))
				_, _ = os.Stderr.WriteString(redacted)
			}
			return
		}
	}
}

// FetchAndCanonicalizeUpstreamTools paginates `session.ListTools` with cursor-loop detection
// and the 250-tool hard cap, returning canonicalized `PinnedToolEntryV1` entries and raw `*mcp.Tool` entries.
func FetchAndCanonicalizeUpstreamTools(
	ctx context.Context,
	session *mcp.ClientSession,
	isRuntimeReverify bool,
) (map[string]*PinnedToolEntryV1, map[string]*mcp.Tool, error) {
	errCode := ErrManifestPinMismatch
	if isRuntimeReverify {
		errCode = ErrManifestRugPullDetected
	}

	seenCursors := map[string]bool{"": true}
	pinnedMap := make(map[string]*PinnedToolEntryV1)
	rawToolMap := make(map[string]*mcp.Tool)
	cursor := ""

	for {
		res, err := session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, nil, NewError(ErrUpstreamProcessTerminated, 0, "upstream tools/list failed: %v", err)
		}
		for _, t := range res.Tools {
			if t == nil || strings.TrimSpace(t.Name) == "" {
				return nil, nil, NewError(errCode, 0, "upstream returned nil or unnamed tool")
			}
			if _, dup := pinnedMap[t.Name]; dup {
				return nil, nil, NewError(errCode, 0, "upstream returned duplicate tool name %q", t.Name)
			}
			if len(pinnedMap)+1 > MaxUpstreamTools {
				return nil, nil, NewError(errCode, 0, "upstream tool count exceeds hard cap %d", MaxUpstreamTools)
			}
			entry, err := canonicalizeMCPTool(t, errCode)
			if err != nil {
				return nil, nil, err
			}
			pinnedMap[t.Name] = entry
			rawToolMap[t.Name] = t
		}
		if res.NextCursor == "" {
			break
		}
		if seenCursors[res.NextCursor] {
			return nil, nil, NewError(errCode, 0, "upstream tools/list cursor loop detected on cursor %q", res.NextCursor)
		}
		seenCursors[res.NextCursor] = true
		cursor = res.NextCursor
	}
	return pinnedMap, rawToolMap, nil
}

func canonicalizeMCPTool(t *mcp.Tool, errCode ErrorCode) (*PinnedToolEntryV1, error) {
	inMap, err := schemaAnyToMap(t.InputSchema)
	if err != nil || inMap == nil {
		return nil, NewError(errCode, 0, "tool %q has invalid inputSchema: %v", t.Name, err)
	}
	outMap, err := schemaAnyToMap(t.OutputSchema)
	if err != nil {
		return nil, NewError(errCode, 0, "tool %q has invalid outputSchema: %v", t.Name, err)
	}

	readOnlyHint := false
	destructiveHint := true
	idempotentHint := false
	openWorldHint := true
	if t.Annotations != nil {
		readOnlyHint = t.Annotations.ReadOnlyHint
		if t.Annotations.DestructiveHint != nil {
			destructiveHint = *t.Annotations.DestructiveHint
		}
		idempotentHint = t.Annotations.IdempotentHint
		if t.Annotations.OpenWorldHint != nil {
			openWorldHint = *t.Annotations.OpenWorldHint
		}
	}

	surface := CanonicalToolSurfaceV1{
		Name:            t.Name,
		Title:           t.Title,
		Description:     t.Description,
		InputSchema:     inMap,
		OutputSchema:    outMap,
		ReadOnlyHint:    readOnlyHint,
		DestructiveHint: destructiveHint,
		IdempotentHint:  idempotentHint,
		OpenWorldHint:   openWorldHint,
	}
	hashHex, err := ComputeToolSurfaceHash(surface)
	if err != nil {
		return nil, NewError(errCode, 0, "compute tool surface hash for %q: %v", t.Name, err)
	}
	return &PinnedToolEntryV1{
		Name:            surface.Name,
		Title:           surface.Title,
		Description:     surface.Description,
		InputSchema:     surface.InputSchema,
		OutputSchema:    surface.OutputSchema,
		ReadOnlyHint:    surface.ReadOnlyHint,
		DestructiveHint: surface.DestructiveHint,
		IdempotentHint:  surface.IdempotentHint,
		OpenWorldHint:   surface.OpenWorldHint,
		ToolSHA256:      hashHex,
	}, nil
}

func schemaAnyToMap(s any) (map[string]any, error) {
	if s == nil {
		return nil, nil
	}
	if m, ok := s.(map[string]any); ok {
		raw, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		if string(raw) == "null" {
			return nil, nil
		}
		val, err := DecodeStrictJSONWithCap(raw, MaxConfigFileBytes, false)
		if err != nil {
			return nil, err
		}
		out, _ := val.(map[string]any)
		return out, nil
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if string(raw) == "null" {
		return nil, nil
	}
	val, err := DecodeStrictJSONWithCap(raw, MaxConfigFileBytes, false)
	if err != nil {
		return nil, err
	}
	out, ok := val.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema is not a JSON object")
	}
	return out, nil
}

// VerifyManifestAgainstLockfile verifies live upstream tools against `lockfile` and `pol` (§4.1.2 & §4.3.1).
func VerifyManifestAgainstLockfile(
	pol *PolicyV1,
	lockfile *ManifestLockfileV1,
	liveTools map[string]*PinnedToolEntryV1,
	isRuntimeReverify bool,
) error {
	mismatchCode := ErrManifestPinMismatch
	if isRuntimeReverify {
		mismatchCode = ErrManifestRugPullDetected
	}

	if lockfile.ServerName != pol.ServerName {
		return NewError(mismatchCode, 0, "lockfile server_name %q != policy server_name %q", lockfile.ServerName, pol.ServerName)
	}
	if len(liveTools) != len(lockfile.Tools) {
		return NewError(mismatchCode, 0, "live upstream tool count %d != pinned lockfile tool count %d", len(liveTools), len(lockfile.Tools))
	}
	for tName, pinned := range lockfile.Tools {
		live, exists := liveTools[tName]
		if !exists {
			return NewError(mismatchCode, 0, "pinned tool %q missing from live upstream manifest", tName)
		}
		if live.ToolSHA256 != pinned.ToolSHA256 {
			return NewError(mismatchCode, 0, "tool %q surface SHA-256 drifted (live %s != pinned %s)", tName, live.ToolSHA256, pinned.ToolSHA256)
		}
	}

	if !isRuntimeReverify {
		// Validate every tool in lockfile against inputSchema / outputSchema subsets
		for tName, pinned := range lockfile.Tools {
			tp := pol.Tools[tName]
			isWrite := tp != nil && (tp.ActionClass == "write:low-risk" || tp.ActionClass == "write:high-risk")
			boundPaths := CollectToolBoundPaths(tp)
			if err := ValidateUpstreamInputSchema(pinned.InputSchema, isWrite, boundPaths); err != nil {
				return err
			}
			if err := ValidateUpstreamOutputSchema(pinned.OutputSchema); err != nil {
				return err
			}
		}

		// Validate every enabled policy tool against the lockfile
		for tName, tp := range pol.Tools {
			if !tp.Enabled {
				continue
			}
			pinned, exists := lockfile.Tools[tName]
			if !exists {
				return NewError(ErrManifestPinMismatch, 0, "enabled policy tool %q is missing from lockfile", tName)
			}
			if tp.ActionClass == "read" && (!pinned.ReadOnlyHint || pinned.DestructiveHint) {
				return NewError(ErrReadClassAnnotationMismatch, 0, "tool %q has action_class \"read\" but lockfile has read_only_hint=%v, destructive_hint=%v",
					tName, pinned.ReadOnlyHint, pinned.DestructiveHint)
			}
			if err := ValidatePolicyPathsAgainstSchema(tName, tp, pinned.InputSchema); err != nil {
				return err
			}
		}
	}
	return nil
}

// PinOptions configures the `mcp-authz-gateway pin` CLI subcommand (§3.3).
type PinOptions struct {
	PolicyPath   string
	Yes          bool
	TTYReader    io.Reader
	StderrWriter io.Writer
}

// PinUpstreamCLI implements `mcp-authz-gateway pin --policy ... [--yes]` (§3.3).
func PinUpstreamCLI(ctx context.Context, opts PinOptions) (*ManifestLockfileV1, error) {
	if opts.StderrWriter == nil {
		opts.StderrWriter = os.Stderr
	}
	pol, err := LoadAndValidatePolicy(opts.PolicyPath)
	if err != nil {
		return nil, err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(pol.Upstream.CallTimeoutMs)*time.Millisecond)
	defer cancel()

	upHandle, err := StartUpstreamSubprocess(timeoutCtx, pol, "", nil, nil, nil)
	if err != nil {
		return nil, err
	}
	defer upHandle.Close()

	liveTools, _, err := FetchAndCanonicalizeUpstreamTools(timeoutCtx, upHandle.Session, false)
	if err != nil {
		return nil, err
	}

	// Validate schemas & policy bindings before writing lockfile
	lf := &ManifestLockfileV1{
		SchemaVersion:        "mcp-authz-lockfile/v1",
		ServerName:           pol.ServerName,
		UpstreamBinarySHA256: upHandle.BinarySHA256,
		Tools:                liveTools,
	}
	if err := VerifyManifestAgainstLockfile(pol, lf, liveTools, false); err != nil {
		return nil, err
	}

	// Print safe ASCII summary to stderr
	toolNames := make([]string, 0, len(liveTools))
	for k := range liveTools {
		toolNames = append(toolNames, k)
	}
	slices.Sort(toolNames)
	fmt.Fprintf(opts.StderrWriter, "=== UPSTREAM MANIFEST PIN SUMMARY ===\n")
	fmt.Fprintf(opts.StderrWriter, "Server Name: %s\n", FormatSafeTerminalASCII(pol.ServerName))
	fmt.Fprintf(opts.StderrWriter, "Binary SHA:  %s\n", FormatSafeTerminalASCII(upHandle.BinarySHA256))
	for _, tn := range toolNames {
		pt := liveTools[tn]
		fmt.Fprintf(opts.StderrWriter, "  - %s (sha256=%s): %s\n",
			FormatSafeTerminalASCII(pt.Name),
			FormatSafeTerminalASCII(pt.ToolSHA256),
			FormatSafeTerminalASCII(pt.Description),
		)
	}

	if !opts.Yes {
		var r io.Reader = opts.TTYReader
		if r == nil {
			ttyFile, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
			if err != nil {
				return nil, NewError(ErrManifestPinMismatch, 0, "cannot open /dev/tty for pin confirmation (use --yes in non-interactive runs): %v", err)
			}
			defer ttyFile.Close()
			r = ttyFile
		}
		fmt.Fprintf(opts.StderrWriter, "Write lockfile to %s? [y/N]: ", FormatSafeTerminalASCII(pol.TCB.LockfilePath))
		sc := bufio.NewScanner(r)
		if !sc.Scan() {
			return nil, NewError(ErrManifestPinMismatch, 0, "pin aborted")
		}
		ans := strings.TrimSpace(sc.Text())
		if ans != "y" && ans != "Y" {
			return nil, NewError(ErrManifestPinMismatch, 0, "pin declined by operator")
		}
	}

	jcsBytes, err := MarshalJCS(lf)
	if err != nil {
		return nil, err
	}
	jcsBytes = append(jcsBytes, '\n')

	tmpPath := pol.TCB.LockfilePath + ".tmp"
	_ = os.Remove(tmpPath)
	f, _, err := OpenVerifiedFile(tmpPath, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY, 0o644, []uint32{0, uint32(os.Geteuid())}, 0o022)
	if err != nil {
		return nil, err
	}
	_, writeErr := f.Write(jcsBytes)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmpPath)
		return nil, NewError(ErrManifestPinMismatch, 0, "write lockfile failed")
	}
	if err := os.Rename(tmpPath, pol.TCB.LockfilePath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	_ = FsyncDir(filepath.Dir(pol.TCB.LockfilePath))
	return lf, nil
}
