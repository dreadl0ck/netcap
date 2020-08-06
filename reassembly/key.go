package reassembly

import (
	"fmt"

	"github.com/dreadl0ck/gopacket"
)

type key [2]gopacket.Flow

func (k *key) String() string {
	return fmt.Sprintf("%s:%s", k[0], k[1])
}

func (k *key) reverse() key {
	return key{
		k[0].Reverse(),
		k[1].Reverse(),
	}
}
