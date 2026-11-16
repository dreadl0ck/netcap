package mpegts

import "errors"

var errBitsShort = errors.New("short elementary header")
var errBitsInvalid = errors.New("invalid elementary header")

type bits struct {
	data     []byte
	position int
	err      error
}

func (b *bits) read(n uint) uint32 {
	if b.err != nil {
		return 0
	}
	if n > 32 || int(n) > len(b.data)*8-b.position {
		b.err = errBitsShort
		return 0
	}
	var value uint32
	for range n {
		value = value<<1 | uint32(b.data[b.position/8]>>(7-b.position%8)&1)
		b.position++
	}
	return value
}
func (b *bits) skip(n uint) {
	for n > 0 {
		step := min(n, 32)
		b.read(step)
		n -= step
	}
}
func (b *bits) ue() uint32 {
	zeros := uint(0)
	for b.err == nil && b.read(1) == 0 {
		zeros++
		if zeros > 31 {
			b.err = errBitsInvalid
			return 0
		}
	}
	if b.err != nil {
		return 0
	}
	return (1 << zeros) - 1 + b.read(zeros)
}
func (b *bits) se() int32 {
	n := b.ue()
	if n&1 != 0 {
		return int32((n + 1) / 2)
	}
	return -int32(n / 2)
}
func rbsp(data []byte) []byte {
	out := make([]byte, 0, min(len(data), 4096))
	zeros := 0
	for _, value := range data {
		if len(out) == 4096 {
			break
		}
		if zeros >= 2 && value == 3 {
			zeros = 0
			continue
		}
		out = append(out, value)
		if value == 0 {
			zeros++
		} else {
			zeros = 0
		}
	}
	return out
}

type SPS struct{ Profile, Level, Width, Height uint32 }

func h264SPS(data []byte) (SPS, error) {
	b := &bits{data: rbsp(data)}
	out := SPS{Profile: b.read(8)}
	b.read(8)
	out.Level = b.read(8)
	b.ue()
	chroma, separate := uint32(1), uint32(0)
	switch out.Profile {
	case 100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135:
		chroma = b.ue()
		if chroma > 3 {
			return out, errBitsInvalid
		}
		if chroma == 3 {
			separate = b.read(1)
		}
		if b.ue() > 6 || b.ue() > 6 {
			return out, errBitsInvalid
		}
		b.read(1)
		if b.read(1) != 0 {
			count := 8
			if chroma == 3 {
				count = 12
			}
			for i := 0; i < count; i++ {
				if b.read(1) == 0 {
					continue
				}
				size := 16
				if i >= 6 {
					size = 64
				}
				last, next := int32(8), int32(8)
				for range size {
					if next != 0 {
						delta := b.se()
						if delta < -128 || delta > 127 {
							return out, errBitsInvalid
						}
						next = (last + delta + 256) % 256
					}
					if next != 0 {
						last = next
					}
				}
			}
		}
	}
	if b.ue() > 12 {
		return out, errBitsInvalid
	}
	switch b.ue() {
	case 0:
		if b.ue() > 12 {
			return out, errBitsInvalid
		}
	case 1:
		b.read(1)
		b.se()
		b.se()
		n := b.ue()
		if n > 255 {
			return out, errBitsInvalid
		}
		for range n {
			b.se()
		}
	case 2:
	default:
		return out, errBitsInvalid
	}
	b.ue()
	b.read(1)
	width, height := b.ue(), b.ue()
	frame := b.read(1)
	if frame == 0 {
		b.read(1)
	}
	b.read(1)
	var left, right, top, bottom uint32
	if b.read(1) != 0 {
		left, right, top, bottom = b.ue(), b.ue(), b.ue(), b.ue()
	}
	if b.err != nil {
		return out, b.err
	}
	if width > 1023 || height > 1023 {
		return out, errBitsInvalid
	}
	x, y := uint32(1), uint32(2-frame)
	if separate == 0 {
		switch chroma {
		case 1:
			x, y = 2, 2*(2-frame)
		case 2:
			x = 2
		}
	}
	w, h := (width+1)*16, (height+1)*16*(2-frame)
	if uint64(left)+uint64(right) > uint64(w/x) || uint64(top)+uint64(bottom) > uint64(h/y) {
		return out, errBitsInvalid
	}
	out.Width, out.Height = w-(left+right)*x, h-(top+bottom)*y
	if out.Width == 0 || out.Height == 0 || out.Width > 16384 || out.Height > 16384 {
		return out, errBitsInvalid
	}
	return out, nil
}

func h265SPS(data []byte) (SPS, error) {
	b := &bits{data: rbsp(data)}
	out := SPS{}
	b.read(4)
	layers := b.read(3)
	b.read(1)
	if layers > 6 {
		return out, errBitsInvalid
	}
	b.read(2)
	b.read(1)
	out.Profile = b.read(5)
	b.skip(32 + 48)
	out.Level = b.read(8)
	var profiles, levels [7]bool
	for i := uint32(0); i < layers; i++ {
		profiles[i] = b.read(1) != 0
		levels[i] = b.read(1) != 0
	}
	if layers > 0 {
		for i := layers; i < 8; i++ {
			b.read(2)
		}
	}
	for i := uint32(0); i < layers; i++ {
		if profiles[i] {
			b.skip(88)
		}
		if levels[i] {
			b.read(8)
		}
	}
	b.ue()
	chroma := b.ue()
	if chroma > 3 {
		return out, errBitsInvalid
	}
	separate := uint32(0)
	if chroma == 3 {
		separate = b.read(1)
	}
	w, h := b.ue(), b.ue()
	var left, right, top, bottom uint32
	if b.read(1) != 0 {
		left, right, top, bottom = b.ue(), b.ue(), b.ue(), b.ue()
	}
	if b.err != nil {
		return out, b.err
	}
	if w == 0 || h == 0 || w > 16384 || h > 16384 {
		return out, errBitsInvalid
	}
	x, y := uint32(1), uint32(1)
	if separate == 0 {
		if chroma == 1 {
			x, y = 2, 2
		} else if chroma == 2 {
			x = 2
		}
	}
	if uint64(left)+uint64(right) > uint64(w/x) || uint64(top)+uint64(bottom) > uint64(h/y) {
		return out, errBitsInvalid
	}
	out.Width, out.Height = w-(left+right)*x, h-(top+bottom)*y
	if out.Width == 0 || out.Height == 0 {
		return out, errBitsInvalid
	}
	return out, nil
}
