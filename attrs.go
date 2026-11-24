package sftp

// ssh_FXP_ATTRS support
// see https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-5

import (
	"os"
	"strconv"
	"time"

	sshfx "github.com/pkg/sftp/internal/encoding/ssh/filexfer"
)

const (
	sshFileXferAttrSize        = 0x00000001
	sshFileXferAttrUIDGID      = 0x00000002
	sshFileXferAttrPermissions = 0x00000004
	sshFileXferAttrACmodTime   = 0x00000008
	sshFileXferAttrExtended    = 0x80000000

	sshFileXferAttrAll = sshFileXferAttrSize | sshFileXferAttrUIDGID | sshFileXferAttrPermissions |
		sshFileXferAttrACmodTime | sshFileXferAttrExtended

	// sshFileXferAttrKnown masks every attribute flag defined by the SFTP
	// protocol. Bits outside this mask are reserved/unknown and must be
	// ignored while decoding rather than treated as an error.
	sshFileXferAttrKnown = sshFileXferAttrAll

	// The SFTP v3 wire format only carries whole-second timestamps.
	// Sub-second precision is transported through extended attributes so
	// that the seconds and the nanoseconds are encoded separately, exactly
	// as the protocol models a timestamp.
	extendedTypeAtimeNSec = "atime-nsec@pkg.sftp"
	extendedTypeMtimeNSec = "mtime-nsec@pkg.sftp"

	// defaultFileMode is the explicit value used for permissions when the
	// caller did not supply any, so the attribute never encodes as an
	// unintentional zero mode.
	defaultFileMode uint32 = 0o644
)

// fileInfo is an artificial type designed to satisfy os.FileInfo.
type fileInfo struct {
	name string
	stat *FileStat
}

// Name returns the base name of the file.
func (fi *fileInfo) Name() string { return fi.name }

// Size returns the length in bytes for regular files; system-dependent for others.
func (fi *fileInfo) Size() int64 { return int64(fi.stat.Size) }

// Mode returns file mode bits.
func (fi *fileInfo) Mode() os.FileMode { return fi.stat.FileMode() }

// ModTime returns the last modification time of the file.
func (fi *fileInfo) ModTime() time.Time { return fi.stat.ModTime() }

// IsDir returns true if the file is a directory.
func (fi *fileInfo) IsDir() bool { return fi.Mode().IsDir() }

func (fi *fileInfo) Sys() any { return fi.stat }

// FileStat holds the original unmarshalled values from a call to READDIR or
// *STAT. It is exported for the purposes of accessing the raw values via
// os.FileInfo.Sys(). It is also used server side to store the unmarshalled
// values for SetStat.
type FileStat struct {
	Size     uint64
	Mode     uint32
	Mtime    uint32
	Atime    uint32
	UID      uint32
	GID      uint32
	Extended []StatExtended

	// MtimeNsec and AtimeNsec hold the nanosecond fractions of Mtime and
	// Atime respectively. The SFTP v3 wire format encodes whole seconds only;
	// the nanoseconds travel alongside the seconds in extended attributes so
	// the two components are encoded separately and a round trip preserves
	// sub-second precision. A zero value means no fractional part.
	MtimeNsec uint32
	AtimeNsec uint32
}

// ModTime returns the Mtime SFTP file attribute converted to a time.Time.
// The conversion only depends on the epoch seconds and nanoseconds of the
// attribute, so the result is identical in every time zone.
func (fs *FileStat) ModTime() time.Time {
	return time.Unix(int64(fs.Mtime), int64(fs.MtimeNsec))
}

// AccessTime returns the Atime SFTP file attribute converted to a time.Time.
// The conversion only depends on the epoch seconds and nanoseconds of the
// attribute, so the result is identical in every time zone.
func (fs *FileStat) AccessTime() time.Time {
	return time.Unix(int64(fs.Atime), int64(fs.AtimeNsec))
}

// FileMode returns the Mode SFTP file attribute converted to an os.FileMode
func (fs *FileStat) FileMode() os.FileMode {
	return toFileMode(fs.Mode)
}

// StatExtended contains additional, extended information for a FileStat.
type StatExtended struct {
	ExtType string
	ExtData string
}

func fileInfoFromStat(stat *FileStat, name string) os.FileInfo {
	return &fileInfo{
		name: name,
		stat: stat,
	}
}

// FileInfoUidGid extends os.FileInfo and adds callbacks for Uid and Gid retrieval,
// as an alternative to *syscall.Stat_t objects on unix systems.
type FileInfoUidGid interface {
	os.FileInfo
	Uid() uint32
	Gid() uint32
}

// FileInfoUidGid extends os.FileInfo and adds a callbacks for extended data retrieval.
type FileInfoExtendedData interface {
	os.FileInfo
	Extended() []StatExtended
}

func fileStatFromInfo(fi os.FileInfo) (uint32, *FileStat) {
	// Unix() and Nanosecond() are zone independent: both reduce the instant
	// to epoch based values, so a difference in client time zones can never
	// change the encoded timestamps.
	mtime := fi.ModTime()
	atime := mtime
	var flags uint32 = sshFileXferAttrSize |
		sshFileXferAttrPermissions |
		sshFileXferAttrACmodTime

	mode := fromFileMode(fi.Mode())
	if mode&uint32(sshfx.ModePerm) == 0 && mode&(s_ISUID|s_ISGID|s_ISVTX) == 0 {
		// No permission bits are available, but the PERMISSIONS flag is
		// set: encode an explicit protocol-allowed default while keeping
		// the file type bits.
		mode |= defaultFileMode
	}

	fileStat := &FileStat{
		Size:      uint64(fi.Size()),
		Mode:      mode,
		Mtime:     uint32(mtime.Unix()),
		Atime:     uint32(atime.Unix()),
		MtimeNsec: uint32(mtime.Nanosecond()),
		AtimeNsec: uint32(atime.Nanosecond()),
	}

	// os specific file stat decoding
	fileStatFromInfoOs(fi, &flags, fileStat)

	// The call above will include the sshFileXferAttrUIDGID in case
	// the os.FileInfo can be casted to *syscall.Stat_t on unix.
	// If fi implements FileInfoUidGid, retrieve Uid, Gid from it instead.
	if fiExt, ok := fi.(FileInfoUidGid); ok {
		flags |= sshFileXferAttrUIDGID
		fileStat.UID = fiExt.Uid()
		fileStat.GID = fiExt.Gid()
	}

	// if fi implements FileInfoExtendedData, retrieve extended data from it
	if fiExt, ok := fi.(FileInfoExtendedData); ok {
		fileStat.Extended = fiExt.Extended()
		if len(fileStat.Extended) > 0 {
			flags |= sshFileXferAttrExtended
		}
	}

	// Keep the nanosecond fractions synchronized as extended attributes so
	// sub-second precision survives encoding; seconds stay in their dedicated
	// fields. The synchronization is idempotent so it is safe both here and
	// again inside marshalFileStat.
	if fileStat.syncTimeNsecExtended() {
		flags |= sshFileXferAttrExtended
	}

	return flags, fileStat
}

// syncTimeNsecExtended makes the timestamp nanosecond extended attributes
// mirror the AtimeNsec/MtimeNsec fields. It is an idempotent upsert: existing
// nsec entries are refreshed, stale ones (a zero nsec field) are removed, and
// any other extended attribute is preserved. It reports whether any nsec
// extended attribute is present.
func (fs *FileStat) syncTimeNsecExtended() bool {
	kept := make([]StatExtended, 0, len(fs.Extended)+2)

	for _, attr := range fs.Extended {
		switch attr.ExtType {
		case extendedTypeAtimeNSec, extendedTypeMtimeNSec:
			// Re-derived below from the dedicated nsec fields.
			continue
		default:
			kept = append(kept, attr)
		}
	}

	if fs.AtimeNsec != 0 {
		kept = append(kept, StatExtended{
			ExtType: extendedTypeAtimeNSec,
			ExtData: strconv.FormatUint(uint64(fs.AtimeNsec), 10),
		})
	}
	if fs.MtimeNsec != 0 {
		kept = append(kept, StatExtended{
			ExtType: extendedTypeMtimeNSec,
			ExtData: strconv.FormatUint(uint64(fs.MtimeNsec), 10),
		})
	}

	fs.Extended = kept
	return fs.AtimeNsec != 0 || fs.MtimeNsec != 0
}

// consumeTimeNsec extracts the timestamp nanosecond fractions carried as
// extended attributes, removing them from the user visible extended slice so
// the decoded FileStat exposes them through the dedicated nsec fields.
// Unknown or malformed nsec entries are left untouched. The slice itself is
// retained (possibly empty) when extended attributes were present, so the
// result still distinguishes "no extended section" from "empty one".
func (fs *FileStat) consumeTimeNsec() {
	kept := fs.Extended[:0]

	for _, attr := range fs.Extended {
		switch attr.ExtType {
		case extendedTypeAtimeNSec:
			if nsec, err := strconv.ParseUint(attr.ExtData, 10, 32); err == nil {
				fs.AtimeNsec = uint32(nsec)

				continue
			}
		case extendedTypeMtimeNSec:
			if nsec, err := strconv.ParseUint(attr.ExtData, 10, 32); err == nil {
				fs.MtimeNsec = uint32(nsec)

				continue
			}
		}

		kept = append(kept, attr)
	}

	fs.Extended = kept
}
