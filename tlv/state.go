package tlv

// stateEntry represents the encoding or decoding state of a TLV.
type stateEntry struct {
	Header

	// Offset indicates how far into the value of the TLV the encoder/decoder has
	// progressed, i.e. how many bytes have been written or read.
	Offset int

	// Length is the maximum length that the TLV value may have. This is at most the
	// length indicated by the header, but may be less if a surrounding TLV is more
	// restrictive. Length is [LengthIndefinite] if no restriction is known.
	Length int
}

// Remaining returns the remaining number of bytes within the value, or
// LengthIndefinite if the length of the element is unknown/indefinite.
func (e *stateEntry) Remaining() int {
	return max(e.Length-e.Offset, LengthIndefinite)
}

// state maintains the state of an [Encoder] or [Decoder]. The state consists of
// a stack of TLVs that are currently being processed. At the bottom of the
// stack there is a virtual constructed indefinite-length TLV representing the
// root level of the input stream.
//
// Note that during processing only the offset of the topmost stateEntry is
// updated. Whenever an element is added or removed from the stack, the state
// type maintains this invariant and updates the new topmost entry.
type state struct {
	stack []stateEntry
	curr  stateEntry // top entry of the stack
}

// reset clears the state to a single root element. The allocated stack space is
// reused.
func (s *state) reset() {
	if s.stack == nil {
		s.stack = make([]stateEntry, 0, 10)
	}
	s.stack = s.stack[:0]
	s.curr = stateEntry{
		Header: Header{Length: LengthIndefinite, Constructed: true},
		Length: LengthIndefinite,
	}
}

// root indicates whether s is currently at the root level.
func (s *state) root() bool {
	return len(s.stack) == 0
}

// push puts h onto the stack, indicating that the value of h is now being
// processed.
func (s *state) push(h Header) {
	prev := s.curr
	s.stack = append(s.stack, s.curr)
	s.curr = stateEntry{
		Header: h,
		Length: MinLength(h.Length, prev.Remaining()),
	}
}

// pop removes the topmost element from the stack and updates the remaining
// state. This indicates that processing of the topmost element is completed.
func (s *state) pop() {
	prev := s.curr
	s.curr = s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
	s.curr.Offset += prev.Offset
}
