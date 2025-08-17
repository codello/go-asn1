package tlv

// stateEntry represents the encoding or decoding state of a TLV.
type stateEntry struct {
	Header

	// Start indicates the input offset where the TLV begins. This is used for error
	// reporting.
	Start int64

	// Offset indicates how far into the value of the TLV the encoder/decoder has
	// progressed, i.e. how many bytes have been written or read.
	Offset int

	// Length is the maximum length that the TLV value may have. This is at most the
	// length indicated by the header, but may be less if a surrounding TLV is more
	// restrictive. Length is [LengthIndefinite] if no restriction is known.
	Length int
}

// Remaining returns the remaining number of bytes within the value, or
// LengthIndefinite if the length of the data value is unknown/indefinite.
func (e *stateEntry) Remaining() int {
	return max(e.Length-e.Offset, LengthIndefinite)
}

// state maintains the state of an [Encoder] or [Decoder]. The state consists of
// a stack of TLVs that are currently being processed. At the bottom of the
// stack there is a virtual constructed indefinite-length TLV representing the
// root level of the input stream.
//
// Note that during processing only the offset of the topmost stateEntry is
// updated. Whenever a data value is added or removed from the stack, the state
// type maintains this invariant and updates the new topmost entry.
type state struct {
	stack []stateEntry
	curr  stateEntry // top entry of the stack

	offset int64
}

// reset clears the state to a single (virtual) root data value. The allocated
// stack space is reused.
func (s *state) reset() {
	if s.stack == nil {
		s.stack = make([]stateEntry, 0, 10)
	}
	s.stack = s.stack[:0]
	s.curr = stateEntry{
		Header: Header{Length: LengthIndefinite, Constructed: true},
		Length: LengthIndefinite,
	}
	s.offset = 0
}

// root indicates whether s is currently at the root level.
func (s *state) root() bool {
	return len(s.stack) == 0
}

// push puts h onto the stack, indicating that the value of h is now being
// processed. The size argument indicates the size of the identifier and length
// octets in bytes.
func (s *state) push(h Header, size int) {
	s.curr.Offset += size
	s.stack = append(s.stack, s.curr)
	s.curr = stateEntry{
		Header: h,
		Start:  s.offset,
		Length: MinLength(h.Length, s.curr.Remaining()),
	}
	s.offset += int64(size)
}

// pop removes the topmost data value from the stack and updates the remaining
// state. This indicates that processing of the value is completed. The given
// size indicates a number of bytes processed from the content octets of the
// current data value.
func (s *state) pop(size int) {
	offset := s.curr.Offset + size
	s.curr = s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
	s.curr.Offset += offset
	s.offset += int64(size)
}
