# Wafris for Caddy

Wafris is an open-source Web Application Firewall (WAF) that runs within Caddy (and other frameworks/ingress applications) powered by Redis. 

Paired with [Wafris Hub](https://wafris.org/hub), you can create rules to block malicious traffic from hitting your application.

![Rules and Graph](https://raw.githubusercontent.com/Wafris/wafris-rb/main/docs/rules-and-graph.png)

Rules like:

- Block IP addresses (IPv6 and IPv4) from making requests
- Block on hosts, paths, user agents, parameters, and methods
- Rate limit (throttle) requests 
- Visualize inbound traffic and requests

Need a better explanation? Read the overview at: [wafris.org](https://wafris.org)


## Installation and Configuration

The Wafris Caddy client is a Caddy module. The module is not included in the default Caddy build, so you will need to build a custom Caddy build that includes the Wafris module.

Once installed, the module communicates with a specifed Redis instance to implement your firewall rules.

## Setup

### 1. Connect to Wafris Hub

Go to https://wafris.org/hub to create a new account and
follow the instructions to link your Redis instance.

**Note:** In Step 3, you'll use this same Redis URL in your app configuration.

### 2. Install the Wafris Caddy module

Either generate a custom Caddy build that includes Wafris from [https://caddyserver.com/download](https://caddyserver.com/download), or use the `xcaddy` utility to build from source:

```
$ xcaddy build --with github.com/wafris/wafris-caddy
```

Download xcaddy at https://github.com/caddyserver/xcaddy

### 3. Set your Redis connection in your Caddyfile

Add the `wafris` directive to your Caddyfile. The directive takes a single argument, which is the Redis URL you received in Step 1.

```nginx
route {
  # this redis url assumes you are running redis on your local machine for testing purposes
  wafris "redis://localhost:6379?protocol=3"
}
```

These routes are usually nesting in a siteblock such as:

```nginx
localhost {
  route {
    wafris "redis://localhost:6379?protocol=3"
  }
}
```
or
```nginx
example.com {
  reverse_proxy :4000 {
  }

  route {
    wafris "redis://localhost:6379?protocol=3"
  }
}
```

Not sure what Redis provider to use? Please read our [Wafris Redis Providers Guide](https://wafris.org/guides/redis-provisioning)


## Trusted Proxies

If you have Cloudflare, Expedited WAF, or another service in front of your application that modifies the `x-forwarded-for` HTTP Request header, please review how to configure [Trusted Proxy Ranges](docs/trusted-proxies.md)


## Help / Support

- Email: [support@wafris.org](mailto:support@wafris.org)
- Twitter: [@wafrisorg](https://twitter.com/wafrisorg)
- Booking: https://app.harmonizely.com/expedited/wafris




<img src='https://uptimer.expeditedsecurity.com/wafris-caddy' width='0' height='0'>
