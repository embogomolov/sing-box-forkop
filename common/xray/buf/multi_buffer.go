package buf

import (
	"io"

	"github.com/sagernet/sing-box/common/xray/errors"
	"github.com/sagernet/sing-box/common/xray/serial"
)

// ReadAllToBytes reads all content from the reader into a byte array, until EOF.
func ReadAllToBytes(reader io.Reader) ([]byte, error) {
	mb, err := ReadFrom(reader)
	if err != nil {
		return nil, err
	}
	if mb.Len() == 0 {
		return nil, nil
	}
	b := make([]byte, mb.Len())
	mb, _ = SplitBytes(mb, b)
	ReleaseMulti(mb)
	return b, nil
}

// MultiBuffer is a list of Buffers. The order of Buffer matters.
type MultiBuffer []*Buffer

// MergeMulti merges content from src to dest, and returns the new address of dest and src
func MergeMulti(dest MultiBuffer, src MultiBuffer) (MultiBuffer, MultiBuffer) {
	dest = append(dest, src...)
	for idx := range src {
		src[idx] = nil
	}
	return dest, src[:0]
}

// MergeBytes merges the given bytes into MultiBuffer and return the new address of the merged MultiBuffer.
func MergeBytes(dest MultiBuffer, src []byte) MultiBuffer {
	n := len(dest)
	if n > 0 && !dest[n-1].IsFull() {
		nBytes, _ := dest[n-1].Write(src)
		src = src[nBytes:]
	}

	for len(src) > 0 {
		b := New()
		nBytes, _ := b.Write(src)
		src = src[nBytes:]
		dest = append(dest, b)
	}

	return dest
}

// ReleaseMulti releases all content of the MultiBuffer, and returns an empty MultiBuffer.
func ReleaseMulti(mb MultiBuffer) MultiBuffer {
	for i := range mb {
		mb[i].Release()
		mb[i] = nil
	}
	return mb[:0]
}

// Copy copied the beginning part of the MultiBuffer into the given byte array.
func (mb MultiBuffer) Copy(b []byte) int {
	total := 0
	for _, bb := range mb {
		nBytes := copy(b[total:], bb.Bytes())
		total += nBytes
		if int32(nBytes) < bb.Len() {
			break
		}
	}
	return total
}

// ReadFrom reads all content from reader until EOF.
func ReadFrom(reader io.Reader) (MultiBuffer, error) {
	mb := make(MultiBuffer, 0, 16)
	for {
		b := New()
		_, err := b.ReadFullFrom(reader, Size)
		if b.IsEmpty() {
			b.Release()
		} else {
			mb = append(mb, b)
		}
		if err != nil {
			if errors.Cause(err) == io.EOF || errors.Cause(err) == io.ErrUnexpectedEOF {
				return mb, nil
			}
			return mb, err
		}
	}
}

// SplitBytes splits the given amount of bytes from the beginning of the MultiBuffer.
// It returns the new address of MultiBuffer leftover, and number of bytes written into the input byte slice.
func SplitBytes(mb MultiBuffer, b []byte) (MultiBuffer, int) {
	totalBytes := 0
	endIndex := -1
	for i := range mb {
		pBuffer := mb[i]
		nBytes, _ := pBuffer.Read(b)
		totalBytes += nBytes
		b = b[nBytes:]
		if !pBuffer.IsEmpty() {
			endIndex = i
			break
		}
		pBuffer.Release()
		mb[i] = nil
	}

	if endIndex == -1 {
		mb = mb[:0]
	} else {
		mb = mb[endIndex:]
	}

	return mb, totalBytes
}

// SplitSize splits the beginning of the MultiBuffer into another one, for at most size bytes.
func SplitSize(mb MultiBuffer, size int32) (MultiBuffer, MultiBuffer) {
	if len(mb) == 0 {
		return mb, nil
	}

	if mb[0].Len() > size {
		b := New()
		copy(b.Extend(size), mb[0].BytesTo(size))
		mb[0].Advance(size)
		return mb, MultiBuffer{b}
	}

	totalBytes := int32(0)
	var r MultiBuffer
	endIndex := -1
	for i := range mb {
		if totalBytes+mb[i].Len() > size {
			endIndex = i
			break
		}
		totalBytes += mb[i].Len()
		r = append(r, mb[i])
		mb[i] = nil
	}
	if endIndex == -1 {
		// To reuse mb array
		mb = mb[:0]
	} else {
		mb = mb[endIndex:]
	}
	return mb, r
}

// Len returns the total number of bytes in the MultiBuffer.
func (mb MultiBuffer) Len() int32 {
	if mb == nil {
		return 0
	}

	size := int32(0)
	for _, b := range mb {
		size += b.Len()
	}
	return size
}

// IsEmpty returns true if the MultiBuffer has no content.
func (mb MultiBuffer) IsEmpty() bool {
	for _, b := range mb {
		if !b.IsEmpty() {
			return false
		}
	}
	return true
}

// String returns the content of the MultiBuffer in string.
func (mb MultiBuffer) String() string {
	v := make([]interface{}, len(mb))
	for i, b := range mb {
		v[i] = b
	}
	return serial.Concat(v...)
}

// MultiBufferContainer is a ReadWriteCloser wrapper over MultiBuffer.
type MultiBufferContainer struct {
	MultiBuffer
}

// Write implements io.Writer.
func (c *MultiBufferContainer) Write(b []byte) (int, error) {
	c.MultiBuffer = MergeBytes(c.MultiBuffer, b)
	return len(b), nil
}
