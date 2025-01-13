package main

import (
	"flag"
	"fmt"

	"github.com/mortimus.com/enum365/pkg/m365"
)

func main() {
	targetDomain := flag.String("t", "contoso.com", "Target domain to lookup info on")
	proxy := flag.String("p", "", "Proxy to use for requests")
	flag.Parse()
	m365.PROXY = *proxy
	err := m365.CheckAutodiscover(*targetDomain)
	if err != nil {
		fmt.Println(err)
	}
	realm, err := m365.GetRealm(*targetDomain)
	if err != nil {
		fmt.Println(err)
	}
	m365.PrintRealm(realm)
	tenantInfo, err := m365.GetTenantInfo(*targetDomain)
	if err != nil {
		fmt.Println(err)
	}
	m365.PrintTenant(tenantInfo)
	env, err := m365.GetAutodiscoverInformation(*targetDomain)
	if err != nil {
		fmt.Printf("Failed to get tenant domains: %s\n", err)
	}
	m365.PrintAutodiscoverEnvelope(env)
	sharepointURL, err := m365.FindSharepointURL(env)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Sharepoint URL: %s\n", sharepointURL)
}
