package wipe

import (
	"bytes"
	"testing"
)

func TestSliceWipe(t *testing.T) {
	// Test case 1: Verify that all bytes are zeroed
	data := []byte{1, 2, 3, 4, 5, 0xFF, 0x00, 0xAA}
	originalLen := len(data)

	SliceWipe(data)

	if len(data) != originalLen {
		t.Errorf("SliceWipe changed the length of the slice: got %d, want %d", len(data), originalLen)
	}

	for i, v := range data {
		if v != 0 {
			t.Errorf("Byte at index %d was not zeroed: got %d", i, v)
		}
	}

	// Test case 2: Verify it works on an empty slice
	empty := []byte{}
	SliceWipe(empty) // Should not panic

	// Test case 3: Verify it works on nil
	var nilSlice []byte
	SliceWipe(nilSlice) // Should not panic

	// Test case 4: Verify it modifies the underlying array (no copy)
	buf := [10]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	slice := buf[2:5] // slice of length 3, indices 2, 3, 4

	SliceWipe(slice)

	expectedBuf := [10]byte{1, 1, 0, 0, 0, 1, 1, 1, 1, 1}
	if !bytes.Equal(buf[:], expectedBuf[:]) {
		t.Errorf("SliceWipe did not modify the expected part of the underlying array.\nGot:  %v\nWant: %v", buf, expectedBuf)
	}
}
