package m365

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var PROXY = "socks5://127.0.0.1:9050"

func NewHTTPClient() (*http.Client, error) {
	if PROXY == "" {
		return &http.Client{}, nil
	}
	u, err := url.Parse(PROXY)
	if err != nil {
		return nil, err
	}
	t := &http.Transport{Proxy: http.ProxyURL(u)}
	return &http.Client{Transport: t}, nil
}

type IPQuery struct {
	IP  string `json:"ip"`
	ISP struct {
		ASN string `json:"asn"`
		Org string `json:"org"`
		ISP string `json:"isp"`
	} `json:"isp"`
	Location struct {
		Country     string  `json:"country"`
		CountryCode string  `json:"country_code"`
		City        string  `json:"city"`
		State       string  `json:"state"`
		Zipcode     string  `json:"zipcode"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		Timezone    string  `json:"timezone"`
		Localtime   string  `json:"localtime"`
	} `json:"location"`
	Risk struct {
		IsMobile     bool `json:"is_mobile"`
		IsVPN        bool `json:"is_vpn"`
		IsTor        bool `json:"is_tor"`
		IsProxy      bool `json:"is_proxy"`
		IsDatacenter bool `json:"is_datacenter"`
		RiskScore    int  `json:"risk_score"`
	} `json:"risk"`
}

func GetPublicIP() (IPQuery, error) {
	tar := "https://api.ipquery.io/?format=json"
	proxy, err := NewHTTPClient()
	if err != nil {
		return IPQuery{}, err
	}
	// get request tar and return the json response
	resp, err := proxy.Get(tar)
	if err != nil {
		return IPQuery{}, err
	}
	var p IPQuery
	err = json.NewDecoder(resp.Body).Decode(&p)
	if err != nil {
		return IPQuery{}, err
	}
	// Get current public IP
	return p, nil
}

func PrintIP(ip IPQuery) {
	// Print current public IP
	fmt.Printf("Current Public IP: %s\n", ip.IP)
	// Print current public IP location
	fmt.Printf("Current Public IP Location: %s, %s, %s, %s, %s\n", ip.Location.Country, ip.Location.CountryCode, ip.Location.City, ip.Location.State, ip.Location.Zipcode)
	// Print current public IP location
	fmt.Printf("Current Public IP Location: %f, %f\n", ip.Location.Latitude, ip.Location.Longitude)
	// Print current public IP location
	fmt.Printf("Current Public IP Location: %s, %s\n", ip.Location.Timezone, ip.Location.Localtime)
	// Print current public IP ISP
	fmt.Printf("Current Public IP ISP: %s, %s, %s\n", ip.ISP.ASN, ip.ISP.Org, ip.ISP.ISP)
	// Print current public IP Risk
	// fmt.Printf("Current Public IP Risk: %t, %t, %t, %t, %t, %d\n", ip.Risk.IsMobile, ip.Risk.IsVPN, ip.Risk.IsTor, ip.Risk.IsProxy, ip.Risk.IsDatacenter, ip.Risk.RiskScore)
	fmt.Printf("Mobile: %t\n", ip.Risk.IsMobile)
	fmt.Printf("VPN: %t\n", ip.Risk.IsVPN)
	fmt.Printf("Tor: %t\n", ip.Risk.IsTor)
	fmt.Printf("Proxy: %t\n", ip.Risk.IsProxy)
	fmt.Printf("Datacenter: %t\n", ip.Risk.IsDatacenter)
	fmt.Printf("Risk Score: %d\n", ip.Risk.RiskScore)
}

func CheckAutodiscover(target string) error {
	const M365 = "autodiscover.outlook.com."
	cname, err := net.LookupCNAME("autodiscover." + target)
	if err != nil {
		return err
	}
	if cname != M365 {
		return errors.New("CNAME is not pointing to M365: " + cname)
	}
	return nil
}

type MicrosoftRealm struct {
	State                   int    `json:"State"`
	UserState               int    `json:"UserState"`
	Login                   string `json:"Login"`
	NameSpaceType           string `json:"NameSpaceType"`
	DomainName              string `json:"DomainName"`
	FederationGlobalVersion int    `json:"FederationGlobalVersion"`
	AuthURL                 string `json:"AuthURL"`
	FederationBrandName     string `json:"FederationBrandName"`
	CloudInstanceName       string `json:"CloudInstanceName"`
	CloudInstanceIssuerUri  string `json:"CloudInstanceIssuerUri"`
}

func GetRealm(domain string) (MicrosoftRealm, error) {
	const URL = "https://login.microsoftonline.com/getuserrealm.srf?login="
	proxy, err := NewHTTPClient()
	if err != nil {
		return MicrosoftRealm{}, err
	}
	// get request tar and return the json response
	resp, err := proxy.Get(URL + domain + "&json=1")
	if err != nil {
		return MicrosoftRealm{}, err
	}
	var realm MicrosoftRealm
	err = json.NewDecoder(resp.Body).Decode(&realm)
	if err != nil {
		return MicrosoftRealm{}, err
	}
	return realm, nil
}

func PrintRealm(realm MicrosoftRealm) {
	// fmt.Printf("State: %d\n", realm.State)
	// fmt.Printf("UserState: %d\n", realm.UserState)
	fmt.Printf("Login: %s\n", realm.Login)
	fmt.Printf("NameSpaceType: %s\n", realm.NameSpaceType)
	fmt.Printf("DomainName: %s\n", realm.DomainName)
	// fmt.Printf("FederationGlobalVersion: %d\n", realm.FederationGlobalVersion)
	fmt.Printf("AuthURL: %s\n", realm.AuthURL)
	fmt.Printf("FederationBrandName: %s\n", realm.FederationBrandName)
	fmt.Printf("CloudInstanceName: %s\n", realm.CloudInstanceName)
	// fmt.Printf("CloudInstanceIssuerUri: %s\n", realm.CloudInstanceIssuerUri)
}

type MicrosoftTenant struct {
	TokenEndpoint                string   `json:"token_endpoint"`
	TokenEndpointAuthMethods     []string `json:"token_endpoint_auth_methods_supported"`
	JWKSURI                      string   `json:"jwks_uri"`
	ResponseModes                []string `json:"response_modes_supported"`
	SubjectTypes                 []string `json:"subject_types_supported"`
	IDTokenSigningAlgValues      []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypes                []string `json:"response_types_supported"`
	Scopes                       []string `json:"scopes_supported"`
	Issuer                       string   `json:"issuer"`
	RequestURIParameterSupported bool     `json:"request_uri_parameter_supported"`
	UserInfoEndpoint             string   `json:"userinfo_endpoint"`
	AuthorizationEndpoint        string   `json:"authorization_endpoint"`
	DeviceAuthorizationEndpoint  string   `json:"device_authorization_endpoint"`
	HTTPLogoutSupported          bool     `json:"http_logout_supported"`
	FrontChannelLogoutSupported  bool     `json:"frontchannel_logout_supported"`
	EndSessionEndpoint           string   `json:"end_session_endpoint"`
	ClaimsSupported              []string `json:"claims_supported"`
	KerberosEndpoint             string   `json:"kerberos_endpoint"`
	TenantRegionScope            string   `json:"tenant_region_scope"`
	TenantRegionSubScope         string   `json:"tenant_region_sub_scope"`
	CloudInstanceName            string   `json:"cloud_instance_name"`
	CloudGraphHostName           string   `json:"cloud_graph_host_name"`
	MSGraphHost                  string   `json:"msgraph_host"`
	RBACURL                      string   `json:"rbac_url"`
}

func GetTenantInfo(domain string) (MicrosoftTenant, error) {
	URL := "https://login.microsoftonline.com/" + domain + "/v2.0/.well-known/openid-configuration"
	proxy, err := NewHTTPClient()
	if err != nil {
		return MicrosoftTenant{}, err
	}
	// get request tar and return the json response
	resp, err := proxy.Get(URL)
	if err != nil {
		return MicrosoftTenant{}, err
	}
	var tenant MicrosoftTenant
	err = json.NewDecoder(resp.Body).Decode(&tenant)
	if err != nil {
		return MicrosoftTenant{}, err
	}
	return tenant, nil
}

func ParseTenantID(tenant MicrosoftTenant) string {
	// Pull tenant ID from TokenEndpoint
	return tenant.TokenEndpoint[len("https://login.microsoftonline.com/") : len(tenant.TokenEndpoint)-len("/oauth2/v2.0/token")]
}

func PrintTenant(tenant MicrosoftTenant) {
	// fmt.Printf("TokenEndpoint: %s\n", tenant.TokenEndpoint)
	// fmt.Printf("TokenEndpointAuthMethods: %v\n", tenant.TokenEndpointAuthMethods)
	// fmt.Printf("JWKSURI: %s\n", tenant.JWKSURI)
	// fmt.Printf("ResponseModes: %v\n", tenant.ResponseModes)
	// fmt.Printf("SubjectTypes: %v\n", tenant.SubjectTypes)
	// fmt.Printf("IDTokenSigningAlgValues: %v\n", tenant.IDTokenSigningAlgValues)
	// fmt.Printf("ResponseTypes: %v\n", tenant.ResponseTypes)
	// fmt.Printf("Scopes: %v\n", tenant.Scopes)
	// fmt.Printf("Issuer: %s\n", tenant.Issuer)
	// fmt.Printf("RequestURIParameterSupported: %t\n", tenant.RequestURIParameterSupported)
	// fmt.Printf("UserInfoEndpoint: %s\n", tenant.UserInfoEndpoint)
	// fmt.Printf("AuthorizationEndpoint: %s\n", tenant.AuthorizationEndpoint)
	// fmt.Printf("DeviceAuthorizationEndpoint: %s\n", tenant.DeviceAuthorizationEndpoint)
	// fmt.Printf("HTTPLogoutSupported: %t\n", tenant.HTTPLogoutSupported)
	// fmt.Printf("FrontChannelLogoutSupported: %t\n", tenant.FrontChannelLogoutSupported)
	// fmt.Printf("EndSessionEndpoint: %s\n", tenant.EndSessionEndpoint)
	// fmt.Printf("ClaimsSupported: %v\n", tenant.ClaimsSupported)
	// fmt.Printf("KerberosEndpoint: %s\n", tenant.KerberosEndpoint)
	fmt.Printf("TenantRegionScope: %s\n", tenant.TenantRegionScope)
	fmt.Printf("TenantRegionSubScope: %s\n", tenant.TenantRegionSubScope)
	// fmt.Printf("CloudInstanceName: %s\n", tenant.CloudInstanceName)
	// fmt.Printf("CloudGraphHostName: %s\n", tenant.CloudGraphHostName)
	// fmt.Printf("MSGraphHost: %s\n", tenant.MSGraphHost)
	// fmt.Printf("RBACURL: %s\n", tenant.RBACURL)
	// print TenantID
	fmt.Printf("TenantID: %s\n", ParseTenantID(tenant))
}

// Get tenant domains
func GetAutodiscoverInformation(domain string) (AutodiscoverEnvelope, error) {
	url := "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
	data := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
	<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
		<soap:Header>
			<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
			<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
			<a:ReplyTo>
				<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
			</a:ReplyTo>
		</soap:Header>
		<soap:Body>
			<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
				<Request>
					<Domain>%s</Domain>
				</Request>
			</GetFederationInformationRequestMessage>
		</soap:Body>
	</soap:Envelope>`, domain)
	headers := map[string]string{
		"Content-Type":    "text/xml; charset=utf-8",
		"SOAPAction":      `"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"`,
		"User-Agent":      "AutodiscoverClient",
		"Accept-Encoding": "identity",
	}
	proxy, err := NewHTTPClient()
	if err != nil {
		return AutodiscoverEnvelope{}, err
	}
	// set the body to data
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return AutodiscoverEnvelope{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := proxy.Do(req)
	if err != nil {
		return AutodiscoverEnvelope{}, err
	}
	// fmt.Println(resp.Body)
	// read the body as xml and pretty print it
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return AutodiscoverEnvelope{}, err
	}
	// fmt.Println(string(b))
	var fed AutodiscoverEnvelope
	err = xml.Unmarshal(b, &fed)
	if err != nil {
		return AutodiscoverEnvelope{}, err
	}
	return fed, nil
}

type AutodiscoverEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Header  struct {
		XMLName xml.Name `xml:"Header"`
		Action  struct {
			XMLName xml.Name `xml:"Action"`
			Must    string   `xml:"mustUnderstand,attr"`
			Text    string   `xml:",chardata"`
		} `xml:"Action"`
		ServerVersionInfo struct {
			XMLName xml.Name `xml:"ServerVersionInfo"`
			Major   int      `xml:"MajorVersion"`
			Minor   int      `xml:"MinorVersion"`
			MajorB  int      `xml:"MajorBuildNumber"`
			MinorB  int      `xml:"MinorBuildNumber"`
			Version string   `xml:"Version"`
		} `xml:"ServerVersionInfo"`
	} `xml:"Header"`
	Body struct {
		XMLName  xml.Name `xml:"Body"`
		Response struct {
			XMLName  xml.Name `xml:"GetFederationInformationResponseMessage"`
			Response struct {
				XMLName        xml.Name `xml:"Response"`
				ErrorCode      string   `xml:"ErrorCode"`
				ErrorMessage   string   `xml:"ErrorMessage"`
				ApplicationUri string   `xml:"ApplicationUri"`
				Domains        struct {
					XMLName xml.Name `xml:"Domains"`
					Domain  []string `xml:"Domain"`
				} `xml:"Domains"`
				TokenIssuers struct {
					XMLName     xml.Name `xml:"TokenIssuers"`
					TokenIssuer struct {
						XMLName  xml.Name `xml:"TokenIssuer"`
						Endpoint string   `xml:"Endpoint"`
						Uri      string   `xml:"Uri"`
					} `xml:"TokenIssuer"`
				} `xml:"TokenIssuers"`
			} `xml:"Response"`
		} `xml:"GetFederationInformationResponseMessage"`
	} `xml:"Body"`
}

func PrintAutodiscoverEnvelope(env AutodiscoverEnvelope) {
	// fmt.Printf("MajorVersion: %d\n", env.Header.ServerVersionInfo.Major)
	// fmt.Printf("MinorVersion: %d\n", env.Header.ServerVersionInfo.Minor)
	// fmt.Printf("MajorBuildNumber: %d\n", env.Header.ServerVersionInfo.MajorB)
	// fmt.Printf("MinorBuildNumber: %d\n", env.Header.ServerVersionInfo.MinorB)
	// fmt.Printf("Version: %s\n", env.Header.ServerVersionInfo.Version)
	// fmt.Printf("ErrorCode: %s\n", env.Body.Response.Response.ErrorCode)
	// fmt.Printf("ErrorMessage: %s\n", env.Body.Response.Response.ErrorMessage)
	// fmt.Printf("ApplicationUri: %s\n", env.Body.Response.Response.ApplicationUri)
	// fmt.Printf("Domains: %v\n", env.Body.Response.Response.Domains.Domain)
	for _, d := range env.Body.Response.Response.Domains.Domain {
		fmt.Printf("Domain: %s\n", d)
	}
	// fmt.Printf("TokenIssuer: %s\n", env.Body.Response.Response.TokenIssuers.TokenIssuer.Uri)
}

func FindSharepointURL(env AutodiscoverEnvelope) (string, error) {
	var sharepointURL string
	for _, d := range env.Body.Response.Response.Domains.Domain {
		if strings.Contains(d, ".mail.onmicrosoft.com") {
			// remove onmicrosoft.com and return the sharepoint url
			d = strings.ReplaceAll(d, ".mail.onmicrosoft.com", "")
			sharepointURL = fmt.Sprintf("https://%s-my.sharepoint.com", d)
			break
		}
		if strings.Contains(d, ".onmicrosoft.com") {
			// remove onmicrosoft.com and return the sharepoint url
			d = strings.ReplaceAll(d, ".onmicrosoft.com", "")
			sharepointURL = fmt.Sprintf("https://%s-my.sharepoint.com", d)
			break
			// return fmt.Sprintf("https://%s-my.sharepoint.com", d)
		}
	}
	if sharepointURL == "" {
		return sharepointURL, errors.New("Failed to find sharepoint URL, please supply")
	}
	// check status of URL
	err := checkStatus(sharepointURL)
	return sharepointURL, err
}

func checkStatus(url string) error {
	proxy, err := NewHTTPClient()
	if err != nil {
		return err
	}
	resp, err := proxy.Get(url)
	if err != nil {
		return err
	}
	fmt.Printf("URL Status: %s\n", resp.Status)
	return nil
}
