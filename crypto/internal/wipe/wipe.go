// Package wipe provides functions for safely zeroing sensitive data in memory.
package wipe

// SliceWipe overwrites the provided byte slice with zeros.
// This is used to clear sensitive data (like private keys or shared secrets) from memory
// after they are no longer needed, mitigating the risk of data leakage.
//
// Arguments:
//   - buf: The byte slice to be zeroed.
func SliceWipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
