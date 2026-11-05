#!/bin/sh
# The Go dispatcher explicitly verifies DSM browser sessions, admins and CSRF.
# Keep this wrapper as a transparent exec with no request-data interpolation so
# DSM receives the Go process status, headers, and body unchanged.
exec /var/packages/dnsacme/target/bin/dnsacme synology api-cgi --config /var/packages/dnsacme/etc/config.yaml
