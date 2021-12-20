![CI Linux][ci-img]
![CI Windows][ci-win-img]
[![Code Coverage][cov-img]][cov-url]
[![Code Climate][clim-img]][clim-url]

[![NPM][npm-img]][npm-url]

# Net-Utils

This module provides network utility functions.

## Usage

    const net_utils = require('haraka-net-utils');

### ip_to_long

    // Convert IPv4 to long
    const long = net_utils.ip_to_long('11.22.33.44');  // 185999660

### long_to_ip

    // Convert long to IPv4
    const ip = net_utils.long_to_ip(185999660);  // 11.22.33.44

### dec_to_hex

    // Convert decimal to hex
    const hex = net_utils.dec_to_hex(20111104);  // 132df00

### hex_to_dec

    // Convert hex to decimal
    const dec = net_utils.hex_to_dec('132df00');  // 20111104

### is_local_ipv4

    // Is IPv4 address on a local network?
    net_utils.is_local_ipv4('127.0.0.200');   // true (localhost)
    net_utils.is_local_ipv4('169.254.0.0');   // true (link local)
    net_utils.is_local_ipv4('226.0.0.1');     // false

### is_private_ipv4

    // Is IPv4 address in RFC 1918 reserved private address space?
    net_utils.is_private_ipv4('10.0.0.0');       // true
    net_utils.is_private_ipv4('192.168.0.0');    // true
    net_utils.is_private_ipv4('172.16.0.0');     // true

### is_local_ipv6

    // Is IPv6 addr on local network?
    net_utils.is_local_ipv6('::1');           // true (localhost)
    net_utils.is_local_ipv6('fe80::')         // true (link local)
    net_utils.is_local_ipv6('fc00::')         // true (unique local)
    net_utils.is_local_ipv6('fd00::')         // true (unique local)

### is_private_ip

    // determines if an IPv4 or IPv6 address is on a "private" network
    // For IPv4, returns true if is_private_ipv4 or is_local_ipv4 are true
    // For IPv6, returns true if is_local_ipv6 is true

### is_local_host

Checks to see if a host name resolves to a local ip.

### is_local_ip

Checks to see if an IP is bound locally or an IPv4 or IPv6 localhost address.

### ip_in_list

    // searches for 'ip' as a hash key in the list object or array
    // ip can be a host, an IP, or an IPv4 or IPv6 range
    net_utils.ip_in_list(object, ip);
    net_utils.ip_in_list(array, ip);
    net_utils.ip_in_list(tls.no_tls_hosts, '127.0.0.5');

### get_mx

    net_utils.get_mx(domain, (err, mxList) => {
        if (err)  // handle any errors
        for (const mx of mxList) {
            // do something with each mx
        }
    })


[ci-img]: https://github.com/haraka/haraka-net-utils/workflows/CI%20Linux/badge.svg
[ci-win-img]: https://github.com/haraka/haraka-net-utils/workflows/CI%20Windows/badge.svg
[cov-img]: https://codecov.io/github/haraka/haraka-net-utils/coverage.svg
[cov-url]: https://codecov.io/github/haraka/haraka-net-utils
[clim-img]: https://codeclimate.com/github/haraka/haraka-net-utils/badges/gpa.svg
[clim-url]: https://codeclimate.com/github/haraka/haraka-net-utils
[npm-img]: https://nodei.co/npm/haraka-net-utils.png
[npm-url]: https://www.npmjs.com/package/haraka-net-utils
