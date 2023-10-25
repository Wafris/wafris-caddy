#!/bin/sh

# format Caddyfile
caddy fmt --overwrite

# build this module, compile it into a custom caddy executable, usually for testing
xcaddy run 