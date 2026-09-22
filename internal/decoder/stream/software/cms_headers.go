package software

// CMSHeaders cmsHeadersList is the list of identifying headers for Content Management Systems and Web Servers.
// the header names will be loaded from the CMS JSON db
// this map is populated once at init and not supposed to change during runtime
// so it is safe for concurrent access.
// nolint
var CMSHeaders = make(map[string]struct{})
