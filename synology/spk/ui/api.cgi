#!/bin/sh
# DSM's package-app route is the authentication, authorization, and CSRF boundary.
# Keep this wrapper as a transparent exec with no request-data interpolation so
# DSM receives the Go process status, headers, and body unchanged.
exec /var/packages/dnsacme/target/bin/dnsacme synology api-cgi --config /var/packages/dnsacme/etc/config.yaml
