package modbus

import (
	"bytes"

	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

type devicePage struct {
	info layers.ModbusDeviceInfo
	at   int64
}
type deviceIDs map[[2]int32]*devicePage

func (ids *deviceIDs) observe(r *types.Modbus, wire []byte) {
	if r.ParseStatus != "valid" || r.MessageRole == "unknown" {
		return
	}
	dir := layers.ModbusRequest
	if r.MessageRole == "response" {
		dir = layers.ModbusResponse
	}
	p, err := layers.DecodeModbusPDU(wire, dir)
	if err != nil {
		return
	}
	r.FunctionName = p.Function.String()
	if p.Exception {
		r.ExceptionName = p.ExceptionCode.String()
		return
	}
	r.StatusWord, r.MessageCount, r.EventCount = uint32(p.Status), uint32(p.MessageCount), uint32(p.EventCount)
	if dir != layers.ModbusResponse || r.MEIType != 14 {
		return
	}
	key := [2]int32{r.UnitID, int32(r.ReadDeviceIDCode)}
	if r.CorrelationStatus != "matched" {
		delete(*ids, key)
		return
	}
	for k, page := range *ids {
		if r.Timestamp < page.at || uint64(r.Timestamp)-uint64(page.at) > uint64(requestTimeout) {
			delete(*ids, k)
		}
	}
	page := (*ids)[key]
	if page != nil {
		_, next, ok := page.info.Next()
		if !ok || uint32(next) != r.DeviceIDObjectID {
			delete(*ids, key)
			page = nil
		}
	}
	if page == nil {
		if r.DeviceIDObjectID != 0 && r.ReadDeviceIDCode != 4 {
			return
		}
		if *ids == nil {
			*ids = make(deviceIDs)
		}
		if len(*ids) >= 32 {
			return
		}
		page = &devicePage{}
		(*ids)[key] = page
	}
	page.at = r.Timestamp
	if err := page.info.Add(&p.DeviceID); err != nil {
		delete(*ids, key)
		return
	}
	if page.info.Complete {
		for _, o := range page.info.Objects {
			r.DeviceIdentity = append(r.DeviceIdentity, &types.ModbusDeviceIDObject{ID: uint32(o.ID), Value: bytes.Clone(o.Value)})
		}
		delete(*ids, key)
	}
}
