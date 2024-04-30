[![CI][ci-img]][ci-url]
[![Code Coverage][cov-img]][cov-url]
[![Code Climate][clim-img]][clim-url]

[![NPM][npm-img]][npm-url]

# Net-Utils

This module provides network utility functions.

## Usage

`const net_utils = require('haraka-net-utils');`

### ip_to_long

```js
// Convert IPv4 to long
const long = net_utils.ip_to_long('11.22.33.44') // 185999660
```

### long_to_ip

```js
// Convert long to IPv4
const ip = net_utils.long_to_ip(185999660) // 11.22.33.44
```

### dec_to_hex

```js
// Convert decimal to hex
const hex = net_utils.dec_to_hex(20111104) // 132df00
```

### hex_to_dec

```js
// Convert hex to decimal
const dec = net_utils.hex_to_dec('132df00') // 20111104
```

### is_local_ipv4

```js
// Is IPv4 address on a local network?
net_utils.is_local_ipv4('127.0.0.200') // true (localhost)
net_utils.is_local_ipv4('169.254.0.0') // true (link local)
net_utils.is_local_ipv4('226.0.0.1') // false
```

### is_private_ipv4

```js
// Is IPv4 address in RFC 1918 reserved private address space?
net_utils.is_private_ipv4('10.0.0.0') // true
net_utils.is_private_ipv4('192.168.0.0') // true
net_utils.is_private_ipv4('172.16.0.0') // true
```

### is_local_ipv6

```js
// Is IPv6 addr on local network?
net_utils.is_local_ipv6('::1') // true (localhost)
net_utils.is_local_ipv6('fe80::') // true (link local)
net_utils.is_local_ipv6('fc00::') // true (unique local)
net_utils.is_local_ipv6('fd00::') // true (unique local)
```

### is_private_ip

Determines if an IPv4 or IPv6 address is on a "private" network.
For IPv4, returns true if is_private_ipv4 or is_local_ipv4 are true
For IPv6, returns true if is_local_ipv6 is true

### is_local_host

Checks to see if a host name matches our server hostname or resolves to any local ip. Local IPs include those bound to a local network interface and public IPs discovered with STUN.

### is_local_ip

Checks to see if an IP is bound locally or an IPv4 or IPv6 localhost address.

### ip_in_list

```js
// searches for 'ip' as a hash key in the list object or array
// ip can be a host, an IP, or an IPv4 or IPv6 range
net_utils.ip_in_list(object, ip)
net_utils.ip_in_list(array, ip)
net_utils.ip_in_list(tls.no_tls_hosts, '127.0.0.5')
```

### get_ips_by_host

Returns an array of all the IPv4 and IPv6 addresses of the provided hostname.

```js
try {
  const ips = await net_utils.get_ips_by_host(domain)
  for (const ip of ips) {
    // do something with the IPs
  }
} catch (err) {
  // handle any errors
}
```

### get_mx

```js
try {
  const mxList = await net_utils.get_mx(domain)
  for (const mx of mxList) {
    // do something with each mx
  }
} catch (err) {
  // handle any errors
}
```

### HarakaMx

An object class representing a MX. HarakaMx objects may contain the following properties:

```js
{
  exchange: '', // required: a FQDN or IP address
  path: '', // the file path to a socket
  priority: 0, // integer, a MX priority.
  port: 25, // integer: an alternate port
  bind: '', // an outbound IP address to bind to
  bind_helo: '', // an outbound helo hostname
  using_lmtp: false, // boolean, specify LMTP delivery
  auth_user: '', // an AUTH username (required if AUTH is desired)
  auth_pass: '', // an AUTH password (required if AUTH is desired)
  auth_type: '', // an AUTH type that should be used with the MX.
  from_dns: '', // the DNS name from which the MX was queried
}
```

Create a HarakaMx object in The Usual Way:

```js
const nu = require('haraka-net-utils')
const myMx = new nu.HarakaMx(parameter)
```

The parameter can be one of:

- A string in any of the following formats:
  - hostname
  - hostname:port
  - IPv4
  - IPv4:port
  - [IPv6]
  - [IPv6]: port
- A [URL](https://nodejs.org/docs/latest-v20.x/api/url.html) string
  - smtp://mail.example.com:25
  - lmtp://int-mail.example.com:24
  - smtp://user:pass@host.example.com:587
- An object, containing at least an exchange, and any of the other properties listed at the top of this section.

An optional second parameter is an alias for from_dns.

[ci-img]: https://github.com/haraka/haraka-net-utils/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/haraka/haraka-net-utils/actions/workflows/ci.yml
[cov-img]: https://codecov.io/github/haraka/haraka-net-utils/coverage.svg
[cov-url]: https://codecov.io/github/haraka/haraka-net-utils
[clim-img]: https://codeclimate.com/github/haraka/haraka-net-utils/badges/gpa.svg
[clim-url]: https://codeclimate.com/github/haraka/haraka-net-utils
[npm-img]: https://nodei.co/npm/haraka-net-utils.png
[npm-url]: https://www.npmjs.com/package/haraka-net-utils
