package main

type profile struct {
	MacAddr            string
	DeviceManufacturer string

	DeviceIPs          []string
	GeolocationHistory []string

	Applications []string

	Contacts []contact
}

type contact struct {
	MacAddr string
	IPs     []string
	// TODO: track frequency and traffic volume as well
}
