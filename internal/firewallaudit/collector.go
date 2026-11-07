package firewallaudit

import (
	"reflect"

	"github.com/dreadl0ck/netcap/internal/collector"
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/packet"
	decoderutils "github.com/dreadl0ck/netcap/internal/decoder/utils"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/gogo/protobuf/proto"
)

// Prepare must run before packet admission for each collector. GoPacket's
// initializer assigns its writer directly; SetWriter installs RecordObserver.
// Other decoder families already use SetWriter during initialization.
func Prepare(c *collector.Collector) error {
	if err := c.Init(); err != nil {
		return err
	}
	dc := config.Instance
	active, err := decoderutils.SelectDecoders(packet.GetGoPacketDecoders(), dc.IncludeDecoders, dc.ExcludeDecoders, func(d *packet.GoPacketDecoder) string { return d.Layer.String() }, packet.ErrInvalidDecoder)
	if err != nil {
		return err
	}
	for _, d := range active {
		w := d.GetWriter()
		if w == nil {
			continue
		}
		// Filtering/rules setup may already have installed this outer wrapper.
		// Obtain its type through the public factory, without depending on its
		// private name or unwrapping another component's writer.
		observed := netio.ObserveWriter(w, func(proto.Message) {})
		if reflect.TypeOf(w) != reflect.TypeOf(observed) {
			d.SetWriter(w)
		}
	}
	return nil
}
