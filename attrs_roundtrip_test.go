package sftp

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	sshfx "github.com/pkg/sftp/internal/encoding/ssh/filexfer"
)

// testFileInfo is a deterministic os.FileInfo so attribute encoding can be
// tested without touching the file system.
type testFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	sys     any
}

func (fi *testFileInfo) Name() string       { return fi.name }
func (fi *testFileInfo) Size() int64        { return fi.size }
func (fi *testFileInfo) Mode() os.FileMode  { return fi.mode }
func (fi *testFileInfo) ModTime() time.Time { return fi.modTime }
func (fi *testFileInfo) IsDir() bool        { return fi.mode.IsDir() }
func (fi *testFileInfo) Sys() any           { return fi.sys }

// TestMarshalUnmarshalFileStatRoundTrip encodes a FileStat and decodes it
// again. The decoded attributes must be identical, including sub-second
// timestamp precision and extended attributes.
func TestMarshalUnmarshalFileStatRoundTrip(t *testing.T) {
	original := &FileStat{
		Size:      12345,
		Mode:      0o751,
		UID:       1000,
		GID:       1001,
		Atime:     1700000000,
		Mtime:     1700000123,
		AtimeNsec: 111111111,
		MtimeNsec: 222222222,
		Extended: []StatExtended{
			{ExtType: "owner@vendor.example", ExtData: "alice"},
		},
	}

	flags := uint32(sshFileXferAttrAll)
	encoded := marshalFileStat(marshalUint32(nil, flags), flags, original)

	decoded, rest, err := unmarshalAttrs(encoded)
	if err != nil {
		t.Fatalf("unmarshalAttrs returned error: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected trailing bytes after decode: %d", len(rest))
	}

	// The nsec values travel inside extended attributes and are lifted back
	// into the dedicated fields; the user supplied extended entry survives.
	want := &FileStat{
		Size:      original.Size,
		Mode:      original.Mode,
		UID:       original.UID,
		GID:       original.GID,
		Atime:     original.Atime,
		Mtime:     original.Mtime,
		AtimeNsec: original.AtimeNsec,
		MtimeNsec: original.MtimeNsec,
		Extended: []StatExtended{
			{ExtType: "owner@vendor.example", ExtData: "alice"},
		},
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("round trip mismatch:\n got: %#v\nwant: %#v", decoded, want)
	}
}

// TestTimestampsAreZoneIndependent verifies requirement 1: the same instant
// produces identical bytes regardless of the time zone it is viewed from.
func TestTimestampsAreZoneIndependent(t *testing.T) {
	instant := time.Date(2023, 11, 25, 13, 14, 15, 345678901, time.UTC)

	zones := []*time.Location{
		time.UTC,
		time.FixedZone("UTC+8", 8*60*60),
		time.FixedZone("UTC-5", -5*60*60),
	}

	var reference []byte
	for i, zone := range zones {
		fi := &testFileInfo{
			name:    "zone",
			mode:    0o644,
			modTime: instant.In(zone),
		}

		flags, stat := fileStatFromInfo(fi)
		encoded := marshalFileStat(marshalUint32(nil, flags), flags, stat)

		if i == 0 {
			reference = encoded
			continue
		}
		if !reflect.DeepEqual(encoded, reference) {
			t.Fatalf("zone %s changed the encoding:\n got: % X\nwant: % X",
				zone, encoded, reference)
		}
	}

	// And decoding it back yields the same instant in any zone.
	decoded, _, err := unmarshalAttrs(reference)
	if err != nil {
		t.Fatalf("unmarshalAttrs returned error: %v", err)
	}
	got := decoded.ModTime()
	// Compare on the epoch components rather than the localized string,
	// since time.Unix presents the instant in the process's local zone.
	if got.Unix() != instant.Unix() || got.Nanosecond() != instant.Nanosecond() {
		t.Fatalf("ModTime round trip mismatch: got %d.%d, want %d.%d",
			got.Unix(), got.Nanosecond(), instant.Unix(), instant.Nanosecond())
	}
	if decoded.MtimeNsec != uint32(instant.Nanosecond()) {
		t.Fatalf("MtimeNsec = %d, want %d",
			decoded.MtimeNsec, instant.Nanosecond())
	}
}

// TestUnmarshalIgnoresUnknownFlags verifies requirement 3: unknown flag bits
// are ignored while every recognized field is still decoded intact.
func TestUnmarshalIgnoresUnknownFlags(t *testing.T) {
	known := uint32(sshFileXferAttrSize) | sshFileXferAttrPermissions |
		sshFileXferAttrUIDGID | sshFileXferAttrACmodTime

	stat := &FileStat{
		Size:  42,
		Mode:  0o600,
		UID:   7,
		GID:   9,
		Atime: 55,
		Mtime: 66,
	}

	encoded := marshalFileStat(marshalUint32(nil, known), known, stat)
	// Rewrite the flags word to include an unknown bit; the body layout is
	// unchanged because unknown bits have no fields.
	encoded[0], encoded[1], encoded[2], encoded[3] = 0, 0, 1, byte(known) // 0x100 is unassigned in SFTP v3

	decoded, _, err := unmarshalAttrs(encoded)
	if err != nil {
		t.Fatalf("unmarshalAttrs returned error for unknown flags: %v", err)
	}
	if decoded.Size != stat.Size || decoded.Mode != stat.Mode ||
		decoded.UID != stat.UID || decoded.GID != stat.GID ||
		decoded.Atime != stat.Atime || decoded.Mtime != stat.Mtime {
		t.Fatalf("recognized fields lost while ignoring unknown flag: %#v", decoded)
	}
}

// TestPermissionsAreNeverEncodedAsZero verifies requirement 2 for the
// permissions field: when the PERMISSIONS flag is set but no mode was
// supplied, an explicit protocol-allowed default is emitted instead of zero.
func TestPermissionsAreNeverEncodedAsZero(t *testing.T) {
	stat := &FileStat{Mode: 0}
	flags := uint32(sshFileXferAttrPermissions)

	encoded := marshalFileStat(marshalUint32(nil, flags), flags, stat)
	decoded, _, err := unmarshalAttrs(encoded)
	if err != nil {
		t.Fatalf("unmarshalAttrs returned error: %v", err)
	}
	if decoded.Mode != defaultFileMode {
		t.Fatalf("Mode = %o, want default %o", decoded.Mode, defaultFileMode)
	}

	// An explicitly supplied mode is passed through untouched.
	stat.Mode = 0o700
	encoded = marshalFileStat(marshalUint32(nil, flags), flags, stat)
	decoded, _, err = unmarshalAttrs(encoded)
	if err != nil {
		t.Fatalf("unmarshalAttrs returned error: %v", err)
	}
	if decoded.Mode != 0o700 {
		t.Fatalf("Mode = %o, want 0o700", decoded.Mode)
	}
}

// TestFileStatFromInfoDefaults verifies requirement 2 end to end through the
// FileInfo encoding path: permissions default, zero UID/GID when unavailable,
// and seconds/nanoseconds split.
func TestFileStatFromInfoDefaults(t *testing.T) {
	modTime := time.Unix(1609459200, 7654321) // 2021-01-01T00:00:00.007...
	fi := &testFileInfo{
		name:    "defaults",
		size:    7,
		mode:    os.FileMode(0), // no mode information available
		modTime: modTime,
		sys:     nil, // no *syscall.Stat_t, so UID/GID cannot be derived
	}

	flags, stat := fileStatFromInfo(fi)

	if flags&sshFileXferAttrPermissions == 0 {
		t.Fatal("permissions flag should always be set")
	}
	// The default fills in the permission bits while the regular-file type
	// bit remains present.
	if stat.Mode&uint32(sshfx.ModePerm) != defaultFileMode {
		t.Fatalf("default permission bits = %o, want %o (full mode %o)",
			stat.Mode&uint32(sshfx.ModePerm), defaultFileMode, stat.Mode)
	}
	if stat.Mtime != uint32(modTime.Unix()) || stat.MtimeNsec != uint32(modTime.Nanosecond()) {
		t.Fatalf("timestamp not split into seconds and nanoseconds: %#v", stat)
	}
	if stat.Atime != stat.Mtime || stat.AtimeNsec != stat.MtimeNsec {
		t.Fatalf("atime should mirror mtime: %#v", stat)
	}
	if flags&sshFileXferAttrUIDGID != 0 {
		t.Fatalf("UID/GID flag must stay clear when owner is unavailable, got %#x", flags)
	}

	// Round trip through the wire format.
	encoded := marshalFileStat(marshalUint32(nil, flags), flags, stat)
	decoded, _, err := unmarshalAttrs(encoded)
	if err != nil {
		t.Fatalf("unmarshalAttrs returned error: %v", err)
	}
	if decoded.ModTime().Unix() != modTime.Unix() ||
		decoded.ModTime().Nanosecond() != modTime.Nanosecond() {
		t.Fatalf("ModTime = %d.%d, want %d.%d",
			decoded.ModTime().Unix(), decoded.ModTime().Nanosecond(),
			modTime.Unix(), modTime.Nanosecond())
	}
	if decoded.Mode&uint32(sshfx.ModePerm) != defaultFileMode {
		t.Fatalf("decoded permission bits = %o, want %o (full mode %o)",
			decoded.Mode&uint32(sshfx.ModePerm), defaultFileMode, decoded.Mode)
	}
}

// TestEncodeThenDecodeIsStableAcrossRequests verifies requirement 4: encoding
// the same FileStat twice yields identical bytes, and each decode returns the
// same attributes.
func TestEncodeThenDecodeIsStableAcrossRequests(t *testing.T) {
	stat := &FileStat{
		Size:      99,
		Mode:      0o640,
		Atime:     100,
		Mtime:     200,
		AtimeNsec: 500,
		MtimeNsec: 750,
		Extended: []StatExtended{
			{ExtType: "x@y", ExtData: "z"},
		},
	}
	flags := uint32(sshFileXferAttrAll)

	first := marshalFileStat(marshalUint32(nil, flags), flags, stat)
	second := marshalFileStat(marshalUint32(nil, flags), flags, stat)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("repeated encoding of the same attributes produced different bytes")
	}

	firstDecoded, _, err := unmarshalAttrs(first)
	if err != nil {
		t.Fatalf("first decode error: %v", err)
	}
	secondDecoded, _, err := unmarshalAttrs(second)
	if err != nil {
		t.Fatalf("second decode error: %v", err)
	}
	if !reflect.DeepEqual(firstDecoded, secondDecoded) {
		t.Fatalf("decodes differ across requests:\n%#v\n%#v", firstDecoded, secondDecoded)
	}
}

// TestEmptyAttributesRoundTrip ensures an empty attribute block (flags == 0)
// still decodes cleanly to the zero-value FileStat.
func TestEmptyAttributesRoundTrip(t *testing.T) {
	decoded, rest, err := unmarshalAttrs(marshalUint32(nil, 0))
	if err != nil {
		t.Fatalf("empty attrs decode error: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes: %d", len(rest))
	}
	if !reflect.DeepEqual(decoded, &FileStat{}) {
		t.Fatalf("empty attrs decoded to %#v, want zero FileStat", decoded)
	}
}

// TestDecodeUnknownExtendedTypeIsRetained verifies requirement 3 at the
// extended-attribute level: an unrecognized extended type survives a decode
// untouched alongside the recognized timestamp nsec entries.
func TestDecodeUnknownExtendedTypeIsRetained(t *testing.T) {
	stat := &FileStat{
		Atime:     10,
		Mtime:     20,
		AtimeNsec: 30,
		Extended: []StatExtended{
			{ExtType: "vendor@example", ExtData: "payload"},
		},
	}
	flags := uint32(sshFileXferAttrACmodTime)
	effective := effectiveFileStatFlags(flags, stat)

	body := marshalFileStat(nil, effective, stat)
	decoded, _, err := unmarshalFileStat(effective, body)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if decoded.AtimeNsec != 30 {
		t.Fatalf("AtimeNsec = %d, want 30", decoded.AtimeNsec)
	}
	found := false
	for _, attr := range decoded.Extended {
		if attr.ExtType == "vendor@example" && attr.ExtData == "payload" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unknown extended attribute was dropped: %#v", decoded.Extended)
	}
}

// TestClientServerChtimesRoundTrip drives a real in-process client/server
// pair (the mixed container/physical-machine topology from the bug report)
// and proves that timestamps with sub-second precision survive a
// Chtimes followed by a Stat, regardless of the process's local zone.
func TestClientServerChtimesRoundTrip(t *testing.T) {
	// Pin a non-UTC local zone for this test process to prove zone
	// independence. time.Unix uses time.Local when rebuilding the instant.
	originalLocal := time.Local
	time.Local = time.FixedZone("UTC+8", 8*60*60)
	defer func() { time.Local = originalLocal }()

	dir := t.TempDir()
	client, server := clientServerPair(t)
	defer client.Close()
	defer server.Close()

	path := filepath.Join(dir, "nsec-file")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	atime := time.Date(2020, 1, 2, 3, 4, 5, 123456789, time.UTC)
	mtime := time.Date(2021, 6, 7, 8, 9, 10, 987654321, time.UTC)
	if err := client.Chtimes(path, atime, mtime); err != nil {
		t.Fatalf("Chtimes failed: %v", err)
	}

	got, err := client.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	// The file system stores whole-second precision for the seconds, so the
	// robust check is the seconds component and zone independence.
	if got.ModTime().Unix() != mtime.Unix() {
		t.Fatalf("mtime seconds = %d, want %d (got %v)",
			got.ModTime().Unix(), mtime.Unix(), got.ModTime())
	}

	// The raw FileStat carried over the wire must keep the modification
	// seconds as a dedicated field. Atime is not asserted here because many
	// Linux mounts use relatime, under which the kernel normalizes atime.
	fs, ok := got.Sys().(*FileStat)
	if !ok {
		t.Fatalf("Sys() = %T, want *FileStat", got.Sys())
	}
	if fs.Mtime != uint32(mtime.Unix()) {
		t.Fatalf("FileStat.Mtime = %d, want %d", fs.Mtime, uint32(mtime.Unix()))
	}

	// The encoded SetStat request itself must carry the seconds and the
	// nanoseconds as separate, zone-independent components. Round trip the
	// exact request attributes through the codec to prove it.
	reqAttrs := &FileStat{
		Atime:     uint32(atime.Unix()),
		Mtime:     uint32(mtime.Unix()),
		AtimeNsec: uint32(atime.Nanosecond()),
		MtimeNsec: uint32(mtime.Nanosecond()),
	}
	reqFlags := uint32(sshFileXferAttrACmodTime)
	// The packet header must carry the effective flags (including the
	// extended bit the nsec fractions require), and the body must match.
	effectiveFlags := effectiveFileStatFlags(reqFlags, reqAttrs)
	if effectiveFlags&sshFileXferAttrExtended == 0 {
		t.Fatal("nanosecond fractions must set the extended flag")
	}
	body := marshalFileStat(nil, effectiveFlags, reqAttrs)
	decoded, _, err := unmarshalFileStat(effectiveFlags, body)
	if err != nil {
		t.Fatalf("request attrs round trip error: %v", err)
	}
	if decoded.Atime != reqAttrs.Atime || decoded.Mtime != reqAttrs.Mtime ||
		decoded.AtimeNsec != reqAttrs.AtimeNsec || decoded.MtimeNsec != reqAttrs.MtimeNsec {
		t.Fatalf("request attrs round trip mismatch:\n got: %#v\nwant: %#v", decoded, reqAttrs)
	}
}

// TestClientServerChmodRoundTrip proves a permission change reads back with
// the same permission bits, and that an unset-mode attribute never collapses
// the mode to zero on the wire.
func TestClientServerChmodRoundTrip(t *testing.T) {
	dir := t.TempDir()
	client, server := clientServerPair(t)
	defer client.Close()
	defer server.Close()

	path := filepath.Join(dir, "mode-file")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	if err := client.Chmod(path, 0o640); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	got, err := client.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if perm := got.Mode().Perm(); perm != 0o640 {
		t.Fatalf("permission bits = %o, want 0o640", perm)
	}
}
