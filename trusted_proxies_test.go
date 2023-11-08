package wafris_caddy

import (
	"fmt"
	"regexp"
	"testing"
)

func TestIsTrustedProxy(t *testing.T) {

	should_be_false := []string{
		"bleair",
		"",
		"104.28.124.69",
		"2a09:bac3:616f:1232::1d0:1c",
		"2a09:bac3:77cc:1250::1d3:80",
		"::0",
		"::2",
		"fbff:ffff:ffff:ffff:ffff:ffff",
		"fe00::",

		"9.255.255.255",
		"11.0.0.0",
		"172.15.0.0",
		"172.32.0.0",
		"192.169.0.0",
		"notlocalhost",
		"localhosttryingtotrickyou",
		"unix:",
	}

	should_be_true := []string{
		// localhost IPv4 range 127.x.x.x, per RFC-3330
		"127.0.0.0",
		"127.0.0.1",
		"127.0.0.255",
		"127.255.255.255",
		// localhost IPv6 ::1
		"::1",
		// private IPv6 range fc00 .. fdff
		"fc00::",
		"fc00:bac3:616f:1232::1d0:1c",
		"fd00:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"fdff::",
		"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		// private IPv4 range 10.x.x.x
		"10.0.0.0",
		"10.0.0.1",
		"10.0.0.255",
		"10.255.255.255",
		// private IPv4 range 172.16.0.0 .. 172.31.255.255
		"172.16.0.0",
		"172.18.21.123",
		"172.31.255.255",
		// private IPv4 range 192.168.x.x
		"192.168.0.0",
		"192.168.1.1",
		"192.168.255.255",
		// localhost hostname, and unix domain sockets
		"localhost",
		"LOCALHOST",
		"LoCaLhOsT",
		"unix",
		"unix:/path/to/socket",
	}

	for i, ip_to_test := range should_be_false {
		t.Run(fmt.Sprintf("index: %d", i), func(t *testing.T) {
			result := IsTrustedProxy(ip_to_test)
			if result != false {
				t.Errorf("ip_to_test: %s, expected false, but got %v", ip_to_test, result)
			}
		})
	}
	for i, ip_to_test := range should_be_true {
		t.Run(fmt.Sprintf("index: %d", i), func(t *testing.T) {
			result := IsTrustedProxy(ip_to_test)
			if result != true {
				t.Errorf("ip_to_test: %s, expected true, but got %v", ip_to_test, result)
			}
		})
	}
}

func TestIsTrustedProxyRegexp(t *testing.T) {

	should_be_false := []string{
		"bleair",
		"",
		"104.28.124.69",
		"2a09:bac3:616f:1232::1d0:1c",
		"2a09:bac3:77cc:1250::1d3:80",
		"::0",
		"::2",
		"fbff:ffff:ffff:ffff:ffff:ffff",
		"fe00::",

		"9.255.255.255",
		"11.0.0.0",
		"172.15.0.0",
		"172.32.0.0",
		"192.169.0.0",
		"notlocalhost",
		"localhosttryingtotrickyou",
		"unix:",
	}

	custom_regexp := []*regexp.Regexp{
		// 100.x.x.x
		regexp.MustCompile(`\A100(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])){3}\z`),
		// 200.100.x.x
		regexp.MustCompile(`\A200.100(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])){2}\z`),
	}

	should_be_true := []string{
		"100.0.0.0",
		"100.0.0.1",
		"100.0.0.255",
		"100.255.255.255",
		"200.100.255.255",
	}

	for i, ip_to_test := range should_be_false {
		t.Run(fmt.Sprintf("index: %d", i), func(t *testing.T) {
			result := isTrustedProxy(ip_to_test, custom_regexp)
			if result != false {
				t.Errorf("ip_to_test: %s, expected false, but got %v", ip_to_test, result)
			}
		})
	}
	for i, ip_to_test := range should_be_true {
		t.Run(fmt.Sprintf("index: %d", i), func(t *testing.T) {
			result := isTrustedProxy(ip_to_test, custom_regexp)
			if result != true {
				t.Errorf("ip_to_test: %s, expected true, but got %v", ip_to_test, result)
			}
		})
	}
}
