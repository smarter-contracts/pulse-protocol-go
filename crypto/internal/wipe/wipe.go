package wipe

// wipe contains functions for safely zeroing sensitive data.

func SliceWipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
