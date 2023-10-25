package wafris_caddy

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
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
	WafrisURL   string `json:"wafris_url,omitempty"`
	logger      *zap.Logger
	redisClient *redis.Client
	coreScript  *redis.Script
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
	sugar.Infoln(2858015990, "wafris-caddy Provision()")

	rclient, err := redisClient(ctx, wc.WafrisURL)
	if err != nil {
		return fmt.Errorf("3025479311 wafris-caddy failure to create redis client: %v", err)
	}

	str_cmd := rclient.ScriptLoad(context.Background(), wafris_core_lua)
	sha := str_cmd.String()

	if strings.Contains(sha, ": ERR ") {
		sugar.Errorln(2858015994, "wafris-caddy sha: \n", sha)

		return fmt.Errorf("1688903171 wafris-caddy : SCRIPT LOAD returned error")
		// } else {
		// sugar.Infoln(2858015994, "wafris-caddy sha:", sha)
	}

	wc.coreScript = redis.NewScript(wafris_core_lua)
	wc.redisClient = rclient

	// sugar.Warnln(2858015995, "coreScript", wc.coreScript)

	return nil
}

// Validate implements caddy.Validator.
func (wc *WafrisCaddy) Validate() error {
	sugar := wc.logger.Sugar()
	sugar.Infoln(2147895300, "wafris-caddy Validate()")

	if wc.WafrisURL == "" {
		return fmt.Errorf("423327974 wafris-caddy : WafrisURL cannot be empty")
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (wc WafrisCaddy) ServeHTTP(rw http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	sugar := wc.logger.Sugar()

	ctx := context.Background()
	rdb := wc.redisClient

	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		sugar.Warnf("req.RemoteAddr: %q is not IP:port", req.RemoteAddr)
		ip = req.RemoteAddr
	}

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

	// Run does EVALSHA or falls back to EVAL, which loads the script so subsequent Runs do EVALSHA
	redis_cmd := wc.coreScript.Run(ctx, rdb, []string{}, args...)
	n, err := redis_cmd.Result()

	if err == nil {
		result_string, isString := n.(string)
		if isString {
			// only for debugging
			// req.Header.Set("X-WafrisResult", result_string)

			if result_string == "Blocked" {
				return writeBlockedResponse(rw)
			}

		} else {
			// result_string is something else
			sugar.Warnf("2548097416 wafris-caddy %T", n)
			sugar.Warnln(2548097417, "wafris-caddy", n)
		}
	} else {
		sugar.Warnln(2548097418, "wafris-caddy", err)
	}

	// debug
	// req.Header.Set("X-Wafris-Result", fmt.Sprintf("%v", n))

	return next.ServeHTTP(rw, req)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (wc *WafrisCaddy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&wc.WafrisURL) {
			return d.ArgErr()
		}
	}
	return nil
}

// parseCaddyfileHandlerDirective parses the `wafris` Caddyfile directive
func parseCaddyfileHandlerDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var wc WafrisCaddy
	err := wc.UnmarshalCaddyfile(h.Dispenser)
	return wc, err
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
