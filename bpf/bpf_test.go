package bpf

import (
	"testing"
)

func TestBPF(t *testing.T) {

	for n := uint8(0); n < 255; n++ {
		c := Pow64(n)      // C implementation
		g := pow64_test(n) // Go implementation below

		if c != g {
			t.Error("pow function result", n, c, g)
		}
	}
}

func pow64_test(x uint8) uint64 {
	switch x {
	case 0:
		return 0x0000000000000001
	case 1:
		return 0x0000000000000002
	case 2:
		return 0x0000000000000004
	case 3:
		return 0x0000000000000008
	case 4:
		return 0x0000000000000010
	case 5:
		return 0x0000000000000020
	case 6:
		return 0x0000000000000040
	case 7:
		return 0x0000000000000080
	case 8:
		return 0x0000000000000100
	case 9:
		return 0x0000000000000200
	case 10:
		return 0x0000000000000400
	case 11:
		return 0x0000000000000800
	case 12:
		return 0x0000000000001000
	case 13:
		return 0x0000000000002000
	case 14:
		return 0x0000000000004000
	case 15:
		return 0x0000000000008000
	case 16:
		return 0x0000000000010000
	case 17:
		return 0x0000000000020000
	case 18:
		return 0x0000000000040000
	case 19:
		return 0x0000000000080000
	case 20:
		return 0x0000000000100000
	case 21:
		return 0x0000000000200000
	case 22:
		return 0x0000000000400000
	case 23:
		return 0x0000000000800000
	case 24:
		return 0x0000000001000000
	case 25:
		return 0x0000000002000000
	case 26:
		return 0x0000000004000000
	case 27:
		return 0x0000000008000000
	case 28:
		return 0x0000000010000000
	case 29:
		return 0x0000000020000000
	case 30:
		return 0x0000000040000000
	case 31:
		return 0x0000000080000000
	case 32:
		return 0x0000000100000000
	case 33:
		return 0x0000000200000000
	case 34:
		return 0x0000000400000000
	case 35:
		return 0x0000000800000000
	case 36:
		return 0x0000001000000000
	case 37:
		return 0x0000002000000000
	case 38:
		return 0x0000004000000000
	case 39:
		return 0x0000008000000000
	case 40:
		return 0x0000010000000000
	case 41:
		return 0x0000020000000000
	case 42:
		return 0x0000040000000000
	case 43:
		return 0x0000080000000000
	case 44:
		return 0x0000100000000000
	case 45:
		return 0x0000200000000000
	case 46:
		return 0x0000400000000000
	case 47:
		return 0x0000800000000000
	case 48:
		return 0x0001000000000000
	case 49:
		return 0x0002000000000000
	case 50:
		return 0x0004000000000000
	case 51:
		return 0x0008000000000000
	case 52:
		return 0x0010000000000000
	case 53:
		return 0x0020000000000000
	case 54:
		return 0x0040000000000000
	case 55:
		return 0x0080000000000000
	case 56:
		return 0x0100000000000000
	case 57:
		return 0x0200000000000000
	case 58:
		return 0x0400000000000000
	case 59:
		return 0x0800000000000000
	case 60:
		return 0x1000000000000000
	case 61:
		return 0x2000000000000000
	case 62:
		return 0x4000000000000000
	case 63:
		return 0x8000000000000000
	}
	return 0
}
