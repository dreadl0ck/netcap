package waf

// Reserve parsing/projection space in addition to the transport's wire buffers.
// apipolicy caps input bytes, nodes, nesting, and schema evaluation work.
const apiValidationCharge int64 = 8 << 20
