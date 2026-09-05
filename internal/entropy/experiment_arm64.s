//go:build entropyexperiment && !purego

#include "textflag.h"

// Scalar, four independent banks. Only load bytes known to be in the slice.
// Interleave updates: batching counter loads regresses repeated-byte throughput.
TEXT ·histogramARM64(SB), NOSPLIT, $0-32
	MOVD data_base+0(FP), R0
	MOVD data_len+8(FP), R1
	MOVD banks+24(FP), R2
	ADD $2048, R2, R3
	ADD $2048, R3, R4
	ADD $2048, R4, R5
loop:
	CMP $4, R1
	BLT tail
	MOVBU (R0), R6
	MOVD (R2)(R6<<3), R10
	ADD $1, R10
	MOVD R10, (R2)(R6<<3)
	MOVBU 1(R0), R7
	MOVD (R3)(R7<<3), R11
	ADD $1, R11
	MOVD R11, (R3)(R7<<3)
	MOVBU 2(R0), R8
	MOVD (R4)(R8<<3), R12
	ADD $1, R12
	MOVD R12, (R4)(R8<<3)
	MOVBU 3(R0), R9
	MOVD (R5)(R9<<3), R13
	ADD $1, R13
	MOVD R13, (R5)(R9<<3)
	ADD $4, R0
	SUB $4, R1
	B loop
tail:
	CBZ R1, done
	MOVBU (R0), R6
	MOVD (R2)(R6<<3), R10
	ADD $1, R10
	MOVD R10, (R2)(R6<<3)
	ADD $1, R0
	SUB $1, R1
	B tail
done:
	RET
