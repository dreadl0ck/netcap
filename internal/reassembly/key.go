package reassembly

import (
	"fmt"

	"github.com/gopacket/gopacket"
)

type key [3]gopacket.Flow

func (k *key) String() string {
	return fmt.Sprintf("%s:%s:%x", k[0], k[1], k[2])
}

func (k *key) reverse() key {
	return key{
		k[0].Reverse(),
		k[1].Reverse(),
		k[2], // tunnel/interface scope is direction independent
	}
}
