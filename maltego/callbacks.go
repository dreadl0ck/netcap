package maltego

import "github.com/dreadl0ck/maltego"

// The selected address can be an IP or MAC, depending on the transform.
type transformationFunc[T any] = func(lt maltego.LocalTransform, trx *maltego.Transform, record *T, min, max uint64, path, address string)

type transformationWithMACFunc[T any] = func(lt maltego.LocalTransform, trx *maltego.Transform, record *T, min, max uint64, path, mac, ip string)

type countFunc[T any] = func(record *T, mac string, min, max *uint64)
