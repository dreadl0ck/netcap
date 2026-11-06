package software

// loadCmsDB clears runtime state without reading legacy CMS files.
func loadCmsDB() error {
	cmsDB = make(map[string]*cmsInfo)
	CMSHeaders = make(map[string]struct{})
	CMSCookies = make(map[string]struct{})
	return nil
}
