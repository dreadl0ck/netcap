package main

type event int

// Define events / actions of interest
const (
	FileDownload event = iota
	FileUpload
	WebsiteVisit
	DeviceChange
	ApplicationUsage
	LocationChange
)
