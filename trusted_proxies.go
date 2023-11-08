package wafris_caddy

import (
	"bytes"
	"net"
	"os"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

const userDefinedProxiesEnvVar string = "TRUSTED_PROXY_RANGES"

var userDefinedProxiesRegexs []*regexp.Regexp

func init() {
	userDefinedProxiesRegexs = []*regexp.Regexp{}
}

func LoadUserDefinedProxies(sugar *zap.SugaredLogger) {
	udp_ev := os.Getenv(userDefinedProxiesEnvVar)

	udps := strings.Split(udp_ev, ",")

	for _, udp_str := range udps {

		normalized_udp_str := strings.TrimSpace(udp_str)
		if len(normalized_udp_str) > 0 {
			compliled_udp, err := regexp.Compile(udp_str)
			if err == nil {
				sugar.Warnln(9358424034, "wafris-caddy regexp added for trusted proxy: ", udp_str)
				userDefinedProxiesRegexs = append(userDefinedProxiesRegexs, compliled_udp)
			} else {
				sugar.Errorln(9358424035, "wafris-caddy regexp failed to compile: ", compliled_udp, err)
			}
		}
	}
}

// we chech three things here:
// 1. user defined regexs
// 2. standard trusted proxy ip ranges
// 3. localhost hostname, and unix domain sockets
func IsTrustedProxy(proxy_to_test string) bool {
	return isTrustedProxy(proxy_to_test, userDefinedProxiesRegexs)
}

// for testing
func isTrustedProxy(proxy_to_test string, custom_regexes []*regexp.Regexp) bool {
	// 1. user defined regexs
	for _, udp := range custom_regexes {
		if udp.MatchString(proxy_to_test) {
			return true
		}
	}

	// 2. standard trusted proxy ip ranges
	req_ip := net.ParseIP(proxy_to_test)

	if req_ip != nil {
		// localhost IPv4 range 127.x.x.x, per RFC-3330
		if IpBetween(net.IPv4(127, 0, 0, 0), net.IPv4(127, 255, 255, 255), req_ip) {
			return true
		}

		// localhost IPv6 ::1
		one := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		if IpBetween(one, one, req_ip) {
			return true
		}

		// private IPv6 range fc00 .. fdff
		fc00 := net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		fdff := net.IP{0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		if IpBetween(fc00, fdff, req_ip) {
			return true
		}

		// private IPv4 range 10.x.x.x
		if IpBetween(net.IPv4(10, 0, 0, 0), net.IPv4(10, 255, 255, 255), req_ip) {
			return true
		}
		// private IPv4 range 172.16.0.0 .. 172.31.255.255
		if IpBetween(net.IPv4(172, 16, 0, 0), net.IPv4(172, 31, 255, 255), req_ip) {
			return true
		}

		// private IPv4 range 192.168.x.x
		if IpBetween(net.IPv4(192, 168, 0, 0), net.IPv4(192, 168, 255, 255), req_ip) {
			return true
		}
	}

	// 3. localhost hostname, and unix domain sockets
	normalized := strings.ToLower(proxy_to_test)
	if normalized == "localhost" {
		return true
	}
	if normalized == "unix" {
		return true
	}
	if strings.HasPrefix(normalized, "unix:") && len(normalized) > 5 {
		return true
	}

	return false
}

func IpBetween(from net.IP, to net.IP, test net.IP) bool {
	if from == nil || to == nil || test == nil {
		return false
	}

	from16 := from.To16()
	to16 := to.To16()
	test16 := test.To16()
	if from16 == nil || to16 == nil || test16 == nil {
		return false
	}

	if bytes.Compare(test16, from16) >= 0 && bytes.Compare(test16, to16) <= 0 {
		return true
	}
	return false
}
