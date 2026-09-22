package maltego

import (
	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
)

// Compile-time checks for literals, alias assignments, and exact type identity.
func callbackAssignability() {
	var http HTTPTransformationFunc = func(maltego.LocalTransform, *maltego.Transform, *types.HTTP, uint64, uint64, string, string) {}
	var genericHTTP transformationFunc[types.HTTP] = http
	http = genericHTTP
	var _ *func(maltego.LocalTransform, *maltego.Transform, *types.HTTP, uint64, uint64, string, string) = &http
	var _ *transformationFunc[types.HTTP] = &http

	var device deviceProfileTransformationFunc = func(maltego.LocalTransform, *maltego.Transform, *types.DeviceProfile, uint64, uint64, string, string) {
	}
	var genericDevice transformationFunc[types.DeviceProfile] = device
	device = genericDevice

	var ssh SSHTransformationFunc = func(maltego.LocalTransform, *maltego.Transform, *types.SSH, uint64, uint64, string, string, string) {}
	var genericSSH transformationWithMACFunc[types.SSH] = ssh
	ssh = genericSSH
	var _ *func(maltego.LocalTransform, *maltego.Transform, *types.SSH, uint64, uint64, string, string, string) = &ssh
	var _ *transformationWithMACFunc[types.SSH] = &ssh

	var host HostTransformationFunc = func(maltego.LocalTransform, *maltego.Transform, *types.Host, uint64, uint64, string, string, string) {
	}
	var ip IPTransformationFunc = host
	var genericHost transformationWithMACFunc[types.Host] = ip
	host = genericHost
	var _ *IPTransformationFunc = &host

	var count SSHCountFunc = func(*types.SSH, string, *uint64, *uint64) {}
	var genericCount countFunc[types.SSH] = count
	count = genericCount
	var _ *func(*types.SSH, string, *uint64, *uint64) = &count
	var _ *countFunc[types.SSH] = &count

	var service serviceCountFunc = func(*types.Service, string, *uint64, *uint64) {}
	var genericService countFunc[types.Service] = service
	service = genericService
}
