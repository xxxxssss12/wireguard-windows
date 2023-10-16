/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"github.com/miekg/dns"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"log"
	"net/netip"
	"time"
	"unsafe"
)

func resolveHostname(name string, dnsServer string, ipv6Priority bool) (resolvedIPString string, err error) {
	maxTries := 10
	if services.StartedAtBoot() {
		maxTries *= 3
	}
	for i := 0; i < maxTries; i++ {
		if i > 0 {
			time.Sleep(time.Second * 4)
		}
		resolvedIPString, err = resolveHostnameOnce(name, dnsServer, ipv6Priority)
		if err == nil {
			return
		}
		if err == windows.WSATRY_AGAIN {
			log.Printf("Temporary DNS error when resolving %s, so sleeping for 4 seconds", name)
			continue
		}
		if err == windows.WSAHOST_NOT_FOUND && services.StartedAtBoot() {
			log.Printf("Host not found when resolving %s at boot time, so sleeping for 4 seconds", name)
			continue
		}
		return
	}
	return
}

func resolveHostnameOnce(name string, dnsServer string, ipv6Priority bool) (resolvedIPString string, err error) {
	// use miekg.dns
	log.Printf("dns resolve: domain=%s, dnsServer= %s, ipv6Priority= %t", name, dnsServer, ipv6Priority)

	if dnsServer != "" {
		log.Printf("miekg.dns resolve ipv6 address: %s", dnsServer)

		c := new(dns.Client)
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
		ipv6, _, err := c.Exchange(m, dnsServer)
		ipv6Addr := ""
		haveIpv6 := false
		if err == nil && len(ipv6.Answer) > 0 {
			for _, ans := range ipv6.Answer {
				if aaaa, ok := ans.(*dns.AAAA); ok {
					haveIpv6 = true
					ipv6Addr = aaaa.AAAA.String()
					log.Printf("miekg.dns resolve ipv6 address: %s", ipv6Addr)
					break
				}
			}
		} else if err != nil {
			log.Printf("miekg.dns get ipv6 err: %s", err)
		}
		m = new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
		ipv4, _, err := c.Exchange(m, dnsServer)
		ipv4Addr := ""
		haveIpv4 := false
		if err == nil && len(ipv4.Answer) > 0 {
			for _, ans := range ipv4.Answer {
				if a, ok := ans.(*dns.A); ok {
					haveIpv4 = true
					ipv4Addr = a.A.String()
					log.Printf("miekg.dns resolve ipv4 address: %s", ipv6Addr)
					break
				}
			}
		} else if err != nil {
			log.Printf("miekg.dns get ipv6 err: %s", err)
		}
		if ipv6Priority && haveIpv6 {
			return ipv6Addr, err
		} else if haveIpv4 {
			return ipv4Addr, err
		} else if haveIpv6 {
			return ipv6Addr, err
		} else {
			log.Printf("miekg.dns don't get result")
		}
	}

	hints := windows.AddrinfoW{
		Family:   windows.AF_UNSPEC,
		Socktype: windows.SOCK_DGRAM,
		Protocol: windows.IPPROTO_IP,
	}
	var result *windows.AddrinfoW
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	err = windows.GetAddrInfoW(name16, nil, &hints, &result)
	if err != nil {
		return
	}
	if result == nil {
		err = windows.WSAHOST_NOT_FOUND
		return
	}
	defer windows.FreeAddrInfoW(result)
	var v6 netip.Addr
	for ; result != nil; result = result.Next {
		if result.Family != windows.AF_INET && result.Family != windows.AF_INET6 {
			continue
		}
		addr := (*winipcfg.RawSockaddrInet)(unsafe.Pointer(result.Addr)).Addr()
		if addr.Is4() {
			return addr.String(), nil
		} else if !v6.IsValid() && addr.Is6() {
			v6 = addr
		}
	}
	if v6.IsValid() {
		return v6.String(), nil
	}
	err = windows.WSAHOST_NOT_FOUND
	return
}

func (config *Config) ResolveEndpoints() error {
	for i := range config.Peers {
		if config.Peers[i].Endpoint.IsEmpty() {
			continue
		}
		var err error
		config.Peers[i].Endpoint.Host, err = resolveHostname(config.Peers[i].Endpoint.Host,
			config.DnsServer, config.Ipv6Priority)
		if err != nil {
			return err
		}
	}
	return nil
}
