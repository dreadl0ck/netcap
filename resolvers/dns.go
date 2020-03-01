package resolvers

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

var timeoutMutex sync.RWMutex
var timeout = 30 * time.Second

// LookupDNSNames retrieves the DNS names associated with an IP addr
// TODO: cache results
func LookupDNSNames(ip string) []string {

	// TODO: not necessary since value cannot be dynamically updated
	timeoutMutex.RLock()
	t := timeout
	timeoutMutex.RUnlock()

	ctx, cancelCtx := context.WithTimeout(context.TODO(), t)
	defer cancelCtx()

	var r net.Resolver
	names, err := r.LookupAddr(ctx, ip)
	if err != nil {
		fmt.Println("net.LookupAddr failed:", err)
	}

	return names
}
