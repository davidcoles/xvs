package bpf

//#include <elf.h>
//#define __u64 uint64_t
//#define __u8 uint8_t
//#include "imports.h"
import "C"

const (
	VETH_ID = C.VETH_ID
	FLOW_S  = 12
	STATE_S = 20

	F_STICKY            = C.F_STICKY
	F_NO_SHARE_FLOWS    = C.F_NO_SHARE_FLOWS
	F_NO_TRACK_FLOWS    = C.F_NO_TRACK_FLOWS
	F_NO_ESTIMATE_CONNS = C.F_NO_ESTIMATE_CONNS
	F_NO_STORE_STATS    = C.F_NO_STORE_STATS
)

func Pow64(x uint8) uint64 {
	return uint64(C.pow64(C.uchar(x)))
	//if x < 0 || x > 63 {
	//	return 0
	//}
	//return 1 << x
}
