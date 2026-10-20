//go:build unix

package authz

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"
)

var knownTestEd25519PubKeysHex = map[string]bool{
	"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a": true, // RFC 8032 §7.1 Test 1
	"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c": true, // RFC 8032 §7.1 Test 2
	"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025": true, // RFC 8032 §7.1 Test 3
	"0000000000000000000000000000000000000000000000000000000000000000": true, // Order 4 (y = 0, sign = 0)
	"0000000000000000000000000000000000000000000000000000000000000080": true, // Order 4 (y = 0, sign = 1)
	"0100000000000000000000000000000000000000000000000000000000000000": true, // Identity point (Order 1)
	"0100000000000000000000000000000000000000000000000000000000000080": true, // Non-canonical identity point
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": true, // Order 2 (y = p - 1)
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05": true, // Order 8 torsion point
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85": true, // Order 8 torsion point
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a": true, // Order 8 torsion point
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa": true, // Order 8 torsion point
}

// ParsedVerifierKey holds a parsed public key and its canonical fingerprint for key-reuse detection.
type ParsedVerifierKey struct {
	Alg         string
	Ed25519Key  ed25519.PublicKey
	ECDSAKey    *ecdsa.PublicKey
	RSAKey      *rsa.PublicKey
	Fingerprint string
}

// ParseEd25519PubKeySpec parses an "ed25519-hex:<64-lowercase-hex>" specification and rejects known RFC 8032 test keys.
func ParseEd25519PubKeySpec(spec string) (ed25519.PublicKey, error) {
	if strings.ContainsAny(spec, "<>") {
		return nil, NewError(ErrKnownTestKeyForbidden, 0, "placeholder public key specification %q is forbidden", spec)
	}
	if !strings.HasPrefix(spec, "ed25519-hex:") {
		return nil, fmt.Errorf("expected prefix \"ed25519-hex:\", got %q", spec)
	}
	hexPart := strings.TrimPrefix(spec, "ed25519-hex:")
	if len(hexPart) != 64 || hexPart != asciiLower(hexPart) {
		return nil, fmt.Errorf("ed25519-hex key must be 64 lowercase hex characters")
	}
	if knownTestEd25519PubKeysHex[hexPart] {
		return nil, NewError(ErrKnownTestKeyForbidden, 0, "known RFC 8032 or weak Ed25519 public key %q is forbidden", hexPart)
	}
	raw, err := hex.DecodeString(hexPart)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 hex public key: %v", err)
	}
	return ed25519.PublicKey(raw), nil
}

// ParseEd25519PrivKeySpec parses "ed25519-priv-hex:<128-lowercase-hex>" (or 64-hex seed) and rejects known test keys.
func ParseEd25519PrivKeySpec(spec string) (ed25519.PrivateKey, error) {
	spec = strings.TrimSpace(spec)
	if !strings.HasPrefix(spec, "ed25519-priv-hex:") {
		return nil, fmt.Errorf("signing key must start with \"ed25519-priv-hex:\"")
	}
	hexPart := strings.TrimPrefix(spec, "ed25519-priv-hex:")
	if hexPart != asciiLower(hexPart) {
		return nil, fmt.Errorf("ed25519-priv-hex key must be lowercase hex")
	}
	raw, err := hex.DecodeString(hexPart)
	if err != nil {
		return nil, fmt.Errorf("invalid hex in signing key: %v", err)
	}
	var priv ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		seed := raw[:ed25519.SeedSize]
		derived := ed25519.NewKeyFromSeed(seed)
		if !slices.Equal(derived, raw) {
			return nil, fmt.Errorf("ed25519 private key suffix does not match seed-derived public key")
		}
		priv = derived
	default:
		return nil, fmt.Errorf("ed25519-priv-hex must be 64 or 128 hex characters")
	}
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	if knownTestEd25519PubKeysHex[pubHex] {
		return nil, NewError(ErrKnownTestKeyForbidden, 0, "known RFC 8032 test signing key is forbidden")
	}
	return priv, nil
}

// ParseVerifierKeySpec parses a public key entry from principal_auth.public_keys.
func ParseVerifierKeySpec(spec string) (*ParsedVerifierKey, error) {
	if strings.ContainsAny(spec, "<>") {
		return nil, NewError(ErrKnownTestKeyForbidden, 0, "placeholder public key %q is forbidden", spec)
	}
	if strings.HasPrefix(spec, "ed25519-hex:") {
		pub, err := ParseEd25519PubKeySpec(spec)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(pub)
		return &ParsedVerifierKey{
			Alg:         "EdDSA",
			Ed25519Key:  pub,
			Fingerprint: "ed25519:" + hex.EncodeToString(sum[:]),
		}, nil
	}

	pemStr := spec
	forcedAlg := ""
	if strings.HasPrefix(spec, "es256-pem:") {
		forcedAlg = "ES256"
		pemStr = strings.TrimPrefix(spec, "es256-pem:")
	} else if strings.HasPrefix(spec, "rs256-pem:") {
		forcedAlg = "RS256"
		pemStr = strings.TrimPrefix(spec, "rs256-pem:")
	}

	block, rest := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("invalid PEM public key specification")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %v", err)
	}
	derBytes, err := x509.MarshalPKIXPublicKey(pubAny)
	if err != nil {
		return nil, err
	}
	fpSum := sha256.Sum256(derBytes)

	switch pub := pubAny.(type) {
	case ed25519.PublicKey:
		if forcedAlg != "" && forcedAlg != "EdDSA" {
			return nil, fmt.Errorf("key type Ed25519 does not match prefix %s", forcedAlg)
		}
		pubHex := hex.EncodeToString(pub)
		if knownTestEd25519PubKeysHex[pubHex] {
			return nil, NewError(ErrKnownTestKeyForbidden, 0, "known RFC 8032 test key is forbidden")
		}
		edSum := sha256.Sum256(pub)
		return &ParsedVerifierKey{
			Alg:         "EdDSA",
			Ed25519Key:  pub,
			Fingerprint: "ed25519:" + hex.EncodeToString(edSum[:]),
		}, nil

	case *ecdsa.PublicKey:
		if forcedAlg != "" && forcedAlg != "ES256" {
			return nil, fmt.Errorf("key type ECDSA does not match prefix %s", forcedAlg)
		}
		if pub.Curve != elliptic.P256() {
			return nil, fmt.Errorf("ES256 requires P-256 curve")
		}
		return &ParsedVerifierKey{
			Alg:         "ES256",
			ECDSAKey:    pub,
			Fingerprint: "pkix:" + hex.EncodeToString(fpSum[:]),
		}, nil

	case *rsa.PublicKey:
		if forcedAlg != "" && forcedAlg != "RS256" {
			return nil, fmt.Errorf("key type RSA does not match prefix %s", forcedAlg)
		}
		if pub.N.BitLen() < 2048 || pub.N.BitLen() > 8192 {
			return nil, fmt.Errorf("RS256 key modulus %d bits must be in [2048, 8192] bits", pub.N.BitLen())
		}
		if pub.E < 3 || pub.E%2 == 0 {
			return nil, fmt.Errorf("RS256 public exponent %d must be an odd integer >= 3", pub.E)
		}
		return &ParsedVerifierKey{
			Alg:         "RS256",
			RSAKey:      pub,
			Fingerprint: "pkix:" + hex.EncodeToString(fpSum[:]),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported public key type %T", pubAny)
	}
}

// PrincipalContext holds the verified caller identity and effective OBO scopes for a request.
type PrincipalContext struct {
	Anonymous      bool
	Sub            string
	IdentityID     string
	Email          string
	TokenDigest    string
	RawJWT         string
	Claims         map[string]any
	HumanScopes    []string
	EffectiveScope map[string]struct{}
}

// VerifyPrincipalJWT performs offline JWS signature verification, header hygiene checks,
// temporal validation, Entra group-overage rejection, identity_claim extraction, and
// PrincipalEmail precedence (email > upn > preferred_username).
func VerifyPrincipalJWT(
	rawJWT string,
	cfg *PrincipalAuthConfig,
	parsedKeys map[string]*ParsedVerifierKey,
	compiledIdentityRegex *regexp.Regexp,
	now time.Time,
) (*PrincipalContext, error) {
	rawJWT = strings.TrimSpace(rawJWT)
	if rawJWT == "" {
		return nil, NewError(ErrPrincipalJWTMissing, 2, "missing subject JWT")
	}

	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "malformed compact JWS serialization")
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "invalid base64url JWS header")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "invalid base64url JWS payload")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "invalid base64url JWS signature")
	}

	hdrObj, err := DecodeStrictJSONObject(hdrBytes, true)
	if err != nil {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "invalid JWS header JSON: %v", err)
	}
	for _, forbiddenHdr := range []string{"jwk", "jku", "x5u", "x5c", "crit"} {
		if _, exists := hdrObj[forbiddenHdr]; exists {
			return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "forbidden JWS header parameter %q", forbiddenHdr)
		}
	}
	if typVal, ok := hdrObj["typ"]; ok {
		typStr, isStr := typVal.(string)
		if !isStr || (asciiLower(typStr) != "jwt" && asciiLower(typStr) != "at+jwt") {
			return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "unsupported JWS typ header %v", typVal)
		}
	}

	algStr, _ := hdrObj["alg"].(string)
	if algStr == "" || !slices.Contains(cfg.AllowedAlgs, algStr) {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWS alg %q not in allowed_algs", algStr)
	}
	kidStr, _ := hdrObj["kid"].(string)
	if kidStr == "" {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "missing JWS kid header")
	}
	vk, ok := parsedKeys[kidStr]
	if !ok || vk.Alg != algStr {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "unknown kid %q or algorithm mismatch", kidStr)
	}

	signingInput := parts[0] + "." + parts[1]
	if err := verifyJWSSignature(vk, signingInput, sigBytes); err != nil {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWS signature verification failed: %v", err)
	}

	claimsObj, err := DecodeStrictJSONObject(payloadBytes, true)
	if err != nil {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "invalid JWS payload JSON: %v", err)
	}

	// §4.2.3 Entra ID / OIDC Group Overage Rejection
	if _, hasNames := claimsObj["_claim_names"]; hasNames {
		return nil, NewError(ErrPrincipalGroupOverageUnsupported, 2, "JWT contains _claim_names group overage indicator")
	}
	if _, hasSources := claimsObj["_claim_sources"]; hasSources {
		return nil, NewError(ErrPrincipalGroupOverageUnsupported, 2, "JWT contains _claim_sources group overage indicator")
	}
	if hg, hasHG := claimsObj["hasgroups"]; hasHG {
		if b, isBool := hg.(bool); isBool && b {
			return nil, NewError(ErrPrincipalGroupOverageUnsupported, 2, "JWT contains hasgroups:true overage indicator")
		}
		if s, isStr := hg.(string); isStr && s != "" && asciiLower(s) != "false" {
			return nil, NewError(ErrPrincipalGroupOverageUnsupported, 2, "JWT contains hasgroups overage indicator")
		}
	}

	// Standard claims: iss, aud, sub, exp, iat, nbf
	iss, _ := claimsObj["iss"].(string)
	if iss == "" || iss != cfg.Issuer {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT issuer %q != configured issuer %q", iss, cfg.Issuer)
	}
	if !matchJWTAudience(claimsObj["aud"], cfg.Audience) {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT audience does not match %q", cfg.Audience)
	}
	sub, _ := claimsObj["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT sub claim is missing or empty")
	}

	expUnix, err := extractIntegralEpochClaim(claimsObj, "exp", true)
	if err != nil {
		return nil, err
	}
	iatUnix, err := extractIntegralEpochClaim(claimsObj, "iat", true)
	if err != nil {
		return nil, err
	}
	nbfUnix, err := extractIntegralEpochClaim(claimsObj, "nbf", false)
	if err != nil {
		return nil, err
	}

	nowUnix := now.Unix()
	skew := cfg.MaxClockSkewSeconds
	if skew < 0 {
		skew = 0
	}
	if nowUnix > expUnix+skew {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT is expired (exp=%d, now=%d)", expUnix, nowUnix)
	}
	if nowUnix < iatUnix-skew {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT iat=%d is in the future (now=%d)", iatUnix, nowUnix)
	}
	if _, hasNbf := claimsObj["nbf"]; hasNbf && nowUnix < nbfUnix-skew {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT nbf=%d is not yet valid (now=%d)", nbfUnix, nowUnix)
	}
	maxLifetime := cfg.MaxTokenLifetimeSeconds
	if maxLifetime <= 0 {
		maxLifetime = 86400
	}
	if expUnix <= iatUnix || (expUnix-iatUnix) > maxLifetime {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT lifetime (%d seconds) invalid or exceeds max_token_lifetime_seconds (%d)", expUnix-iatUnix, maxLifetime)
	}

	// Canonical PrincipalIdentityID from identity_claim
	idClaimName := cfg.IdentityClaim
	if idClaimName == "" {
		idClaimName = "sub"
	}
	rawIDVal, exists := claimsObj[idClaimName]
	if !exists {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT missing configured identity_claim %q", idClaimName)
	}
	rawIDStr, ok := rawIDVal.(string)
	if !ok || strings.TrimSpace(rawIDStr) == "" {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT identity_claim %q must be a non-empty string", idClaimName)
	}
	normID, err := NormalizeIdentifier(rawIDStr, "id_alnum", compiledIdentityRegex, cfg.IdentityCaseMode)
	if err != nil {
		return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT identity_claim %q value %q failed canonical validation: %v", idClaimName, rawIDStr, err)
	}

	// Deterministic PrincipalEmail extraction with precedence: email > upn > preferred_username.
	// Every present claim among the three must pass email_or_upn normalization.
	var principalEmail string
	for _, emailKey := range []string{"email", "upn", "preferred_username"} {
		val, present := claimsObj[emailKey]
		if !present || val == nil {
			continue
		}
		strVal, isStr := val.(string)
		if !isStr || strings.TrimSpace(strVal) == "" {
			return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT claim %q must be a non-empty email string", emailKey)
		}
		normEmail, err := NormalizeIdentifier(strVal, "email_or_upn", nil, "ascii_lower")
		if err != nil {
			return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT claim %q failed email_or_upn validation: %v", emailKey, err)
		}
		if principalEmail == "" {
			principalEmail = normEmail
		}
	}

	tokHash := sha256.Sum256([]byte(rawJWT))
	return &PrincipalContext{
		Anonymous:   false,
		Sub:         sub,
		IdentityID:  normID,
		Email:       principalEmail,
		TokenDigest: hex.EncodeToString(tokHash[:]),
		RawJWT:      rawJWT,
		Claims:      claimsObj,
	}, nil
}

func verifyJWSSignature(vk *ParsedVerifierKey, signingInput string, sigBytes []byte) error {
	switch vk.Alg {
	case "EdDSA":
		if len(sigBytes) != ed25519.SignatureSize {
			return fmt.Errorf("EdDSA signature length %d != %d", len(sigBytes), ed25519.SignatureSize)
		}
		if !ed25519.Verify(vk.Ed25519Key, []byte(signingInput), sigBytes) {
			return fmt.Errorf("Ed25519 signature invalid")
		}
		return nil

	case "ES256":
		// RFC 7515 §A.3 requires raw 64-byte R || S fixed-width concatenation (NOT ASN.1 DER).
		if len(sigBytes) != 64 {
			return fmt.Errorf("ES256 signature must be raw 64-byte R||S, got %d bytes", len(sigBytes))
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		curveOrder := elliptic.P256().Params().N
		if r.Sign() <= 0 || r.Cmp(curveOrder) >= 0 || s.Sign() <= 0 || s.Cmp(curveOrder) >= 0 {
			return fmt.Errorf("ES256 R or S out of curve bounds")
		}
		digest := sha256.Sum256([]byte(signingInput))
		if !ecdsa.Verify(vk.ECDSAKey, digest[:], r, s) {
			return fmt.Errorf("ES256 signature invalid")
		}
		return nil

	case "RS256":
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(vk.RSAKey, crypto.SHA256, digest[:], sigBytes); err != nil {
			return fmt.Errorf("RS256 signature invalid: %v", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported algorithm %q", vk.Alg)
	}
}

func matchJWTAudience(audClaim any, expected string) bool {
	if expected == "" {
		return false
	}
	switch v := audClaim.(type) {
	case string:
		return v == expected
	case []any:
		if len(v) == 0 {
			return false
		}
		found := false
		for _, elem := range v {
			s, ok := elem.(string)
			if !ok || s == "" {
				return false
			}
			if s == expected {
				found = true
			}
		}
		return found
	default:
		return false
	}
}

func extractIntegralEpochClaim(claims map[string]any, name string, required bool) (int64, error) {
	raw, ok := claims[name]
	if !ok {
		if required {
			return 0, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "missing required JWT temporal claim %q", name)
		}
		return 0, nil
	}
	f, ok := raw.(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || math.Trunc(f) != f || f <= 0 || f > float64(MaxSafeInt53) {
		return 0, NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT temporal claim %q must be a positive integer number", name)
	}
	return int64(f), nil
}
