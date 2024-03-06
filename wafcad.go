package wafris_caddy

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(WafrisCaddy{})
	httpcaddyfile.RegisterHandlerDirective("wafris", parseCaddyfileHandlerDirective)
}

// Wafris, a free, open source WAF (web application firewall)
type WafrisCaddy struct {
	WafrisURL     string  `json:"wafris_url,omitempty"`
	WafrisTimeout float64 `json:"wafris_timeout,omitempty"` //in seconds
	logger        *zap.Logger
	redisClient   *redis.Client
	coreScript    *redis.Script
}

// CaddyModule returns the Caddy module information.
func (WafrisCaddy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.wafris",
		New: func() caddy.Module { return new(WafrisCaddy) },
	}
}

func redisClient(ctx caddy.Context, url string) (*redis.Client, error) {
	// sugar := ctx.Logger().Sugar()
	// caution, this may expose redis password in logs!
	// sugar.Infoln(3637760338, "wafris-caddy creating redis client with url:", url)

	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("redis.ParseURL err: %v", err)
	}
	// caution, this may expose redis password in logs!
	// sugar.Warnln(3637760339, "wafris-caddy creating redis client with opts", opts)
	rdb := redis.NewClient(opts)

	return rdb, nil
}

// Provision sets up the module.
func (wc *WafrisCaddy) Provision(ctx caddy.Context) error {

	wc.logger = ctx.Logger() // g.logger is a *zap.Logger
	sugar := wc.logger.Sugar()
	sugar.Debugln(2858015990, "[Wafris] Provision()")

	rclient, err := redisClient(ctx, wc.WafrisURL)
	if err != nil {
		return fmt.Errorf("3025479311 [Wafris] failure to create redis client: %v", err)
	}

	str_cmd := rclient.ScriptLoad(context.Background(), wafris_core_lua)
	sha_or_err := str_cmd.String()

	if strings.Contains(sha_or_err, ": ERR ") {
		return fmt.Errorf("9688903171 [Wafris] SCRIPT LOAD returned error: %v", sha_or_err)
	}

  // Assuming the script load is successful, now create the hash.
  _, err = rclient.HSet(context.Background(), "waf-settings", "version", "v0.0.1", "client", "wafris-caddy").Result()
  if err != nil {
      return fmt.Errorf("error setting waf-settings: %v", err)
  }

	wc.coreScript = redis.NewScript(wafris_core_lua)
	wc.redisClient = rclient

	LoadUserDefinedProxies(sugar)

	// sugar.Debugln(2858015995, "[Wafris] coreScript", wc.coreScript)

	return nil
}

// Validate implements caddy.Validator.
func (wc *WafrisCaddy) Validate() error {
	sugar := wc.logger.Sugar()
	sugar.Debugln(2147895300, "[Wafris] Validate()")

	if wc.WafrisURL == "" {
		return fmt.Errorf("423327974 [Wafris] WafrisURL cannot be empty")
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (wc WafrisCaddy) ServeHTTP(rw http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	sugar := wc.logger.Sugar()

	rdb := wc.redisClient

	ip := getRealIp(req, sugar)

	// sugar.Debugf("2659600773 req getRealIp           ip: %v", ip)
	// sugar.Debugf("2659600774 req.Get    x-forwarded-for: %v", req.Header.Get("x-forwarded-for"))
	// sugar.Debugf("2659600775 req.Values x-forwarded-for: %v", req.Header.Values("x-forwarded-for"))

	parsed_ip := net.ParseIP(ip)

	args := []interface{}{
		//ip
		ip,
		// ip integer string
		Ip2IntString(parsed_ip),
		// time
		time.Now().UnixMilli(),
		// request user agent
		req.UserAgent(),
		// request path
		req.URL.RawPath,
		// request query string
		req.URL.RawQuery,
		// request host
		req.Host,
		// request method
		req.Method,
	}

	ctx := context.Background()
	if wc.WafrisTimeout > 0 {
		timeout_duration := time.Duration(wc.WafrisTimeout * float64(time.Second))
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, timeout_duration)
		defer cancel()
	}

	ch := make(chan *redis.Cmd)

	go func() {
		select {
		// Run does EVALSHA or falls back to EVAL, which loads the script so subsequent Runs do EVALSHA
		case ch <- wc.coreScript.Run(ctx, rdb, []string{}, args...):
		default:
			return
		}
	}()

	var redis_cmd *redis.Cmd
	select {
	case <-ctx.Done():
		sugar.Infoln("2724205532 [Wafris] Wafris timed out during processing. Request passed without rules check.")

		return next.ServeHTTP(rw, req)

	case result := <-ch:
		redis_cmd = result
	}

	n, err := redis_cmd.Result()

	if err == nil {
		result_string, isString := n.(string)
		if isString {
			// only for debugging
			// req.Header.Set("X-WafrisResult", result_string)

			if result_string == "Blocked" {
				sugar.Infoln("2548097413 [Wafris] Blocked:", ip, req.Method, req.Host, req.URL.String())
				return writeBlockedResponse(rw)
			}

		} else {
			// result_string is something else
			sugar.Warnf("2548097416 [Wafris] Redis returned type that wasn't a string: %T, value: %v. Request passed without rules check.", n, n)
		}
	} else {
		sugar.Warnln(2548097418, "[Wafris] Redis connection error:", err, "Request passed without rules check.")
	}

	// debug
	// req.Header.Set("X-Wafris-Result", fmt.Sprintf("%v", n))
	// Pass by default if something is wrong with Redis
	return next.ServeHTTP(rw, req)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (wc *WafrisCaddy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {

	if d.CountRemainingArgs() == 2 {
		// if d.CountRemainingArgs() == 2 that means we have:
		//     wafris SOME_REDIS_URL
		// where the first arg is wafris and the second arg is SOME_REDIS_URL

		// calling d.Next() pops wafris of the dispenser fifo and the next time we call d.Args() it should give us SOME_REDIS_URL
		for d.Next() {
			if !d.Args(&wc.WafrisURL) {
				return fmt.Errorf("12046737182 [Wafris] %v", d.ArgErr())
			}
		}
	} else {
		// if d.CountRemainingArgs() == 1 that means we expect:
		//     wafris {
		//         url SOME_REDIS_URL
		//         timeout TIMEOUT_IN_SECONDS
		//     }
		// the {} and everything in it counts as one block and we have to nest down into it.

		// pop wafris off the fifo
		for d.Next() {
			// nest into the block of subdirectives
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				// log.Println(2937386010, "val", d.Val())

				// d.Val() should either be `url` or `timeout` only.
				switch d.Val() {
				case "url":
					if !d.Args(&wc.WafrisURL) {
						return fmt.Errorf("1204673717 [Wafris] %v", d.ArgErr())
					}
				case "timeout":
					var timeout_string string
					if !d.Args(&timeout_string) {
						return fmt.Errorf("1204673718 [Wafris] %v", d.ArgErr())
					}

					// log.Printf("4143840214 %T %v", timeout_string, timeout_string)

					timeout_in_seconds, err := strconv.ParseFloat(timeout_string, 64)
					if err != nil {
						return fmt.Errorf("1204673719 [Wafris] cannot parse timeout in seconds: %v", timeout_string)
					}

					wc.WafrisTimeout = timeout_in_seconds

				default:
					return fmt.Errorf("1204673730 [Wafris] unexpected subdirective %v", d.ArgErr())

				}
			}
		}
	}
	// log.Println(8747176953, "wc.WafrisURL", wc.WafrisURL)
	// log.Printf("8747176955 wc.WafrisTimeout %g", wc.WafrisTimeout)
	return nil
}

// parseCaddyfileHandlerDirective parses the `wafris` Caddyfile directive
func parseCaddyfileHandlerDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var wc WafrisCaddy
	err := wc.UnmarshalCaddyfile(h.Dispenser)
	return wc, err
}

// best effort based on x-forwarded-for and RemoteAddr
func getRealIp(req *http.Request, sugar *zap.SugaredLogger) string {
	// var err error
	xff_values := req.Header.Values("x-forwarded-for")

	if len(xff_values) != 0 {
		// reverse the slice
		for i, j := 0, len(xff_values)-1; i < j; i, j = i+1, j-1 {
			xff_values[i], xff_values[j] = xff_values[j], xff_values[i]
		}

		// sugar.Debugf("req.xff_values: %v", xff_values)

		for _, ip := range xff_values {
			// sugar.Debugf("3450939168 req.IsTrustedProxy: %v, %v", ip, IsTrustedProxy(ip))
			if !IsTrustedProxy(ip) {
				// ues this one
				return ip
			}
		}
	}

	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		sugar.Errorf("req.RemoteAddr: %q is not IP:port", req.RemoteAddr)
		ip = req.RemoteAddr
	}
	return ip
}

// https://andrew.red/posts/golang-ipv4-ipv6-to-decimal-integer
func Ip2IntString(ip net.IP) string {
	if ip == nil {
		return "0"
	}

	big_int := big.NewInt(0)
	big_int.SetBytes(ip)
	return big_int.String()
}

func writeBlockedResponse(w http.ResponseWriter) error {
	w.WriteHeader(http.StatusForbidden)
	io.WriteString(w, "Blocked")
	return nil
}
