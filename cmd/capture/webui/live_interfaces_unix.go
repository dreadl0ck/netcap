//go:build !windows

package webui

func liveInterfaces() ([]NetworkInterfaceInfo, error) { return systemNetworkInterfaces() }
