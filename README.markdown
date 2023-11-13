# Wafris caddy plugin 

Wafris: https://wafris.org

Caddy: https://caddyserver.com


## Install

Like most all Caddy plugins, [select it on the download page](https://caddyserver.com/download) to get a custom build, or use xcaddy to build from source:

```
$ xcaddy build --with github.com/Wafris/wafris-caddy
```

xcaddy: https://github.com/caddyserver/xcaddy


## Usage


### Redis

1. Setup a working redis instance
2. Get your redis URL

### Define a route in your Caddyfile:

    route {
      # this redis url assumes you are running redis on your local machine for testing purposes
      wafris "redis://localhost:6379?protocol=3"
    }

These routes are usually nesting in a siteblock such as:

    localhost {
      route {
        wafris "redis://localhost:6379?protocol=3"
      }
    }

or

    example.com {
      reverse_proxy :4000 {
      }

      route {
        wafris "redis://localhost:6379?protocol=3"
      }
    }

### Wafris.org 

1. Sign in to or register a new account at wafris.org
2. Add your redis URL
3. Add any necessay block rules

<img src='https://uptimer.expeditedsecurity.com/wafris-caddy' width='0' height='0'>
