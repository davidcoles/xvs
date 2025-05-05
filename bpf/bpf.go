package bpf

//#include <elf.h>
//#define __u64 uint64_t
//#define __u8 uint8_t
//#include "imports.h"
import "C"

const (
	F_CHECKSUM_DISABLE = C.F_CHECKSUM_DISABLE
	F_STICKY           = C.F_STICKY

	T_NONE = C.T_NONE
	T_FOU  = C.T_FOU
	T_GRE  = C.T_GRE
	T_GUE  = C.T_GUE
	T_IPIP = C.T_IPIP
)

func Pow64(x uint8) uint64 {
	return uint64(C.pow64(C.uchar(x)))
}
