'use strict';

// node.js built-ins
const dns      = require('dns');
const net      = require('net');
const os       = require('os');
const punycode = require('punycode')

// npm modules
const async    = require('async');
const ipaddr   = require('ipaddr.js');
const sprintf  = require('sprintf-js').sprintf;
const tlds     = require('haraka-tld');

const locallyBoundIPs = [];

// export config, so config base path can be overloaded by tests
exports.config = require('haraka-config');

exports.long_to_ip = function (n) {
  let d = n%256;
  for (let i=3; i>0; i--) {
    n = Math.floor(n/256);
    d = `${n%256}.${d}`;
  }
  return d;
}

exports.dec_to_hex = function (d) {
  return d.toString(16);
}

exports.hex_to_dec = function (h) {
  return parseInt(h, 16);
}

exports.ip_to_long = function (ip) {
  if (!net.isIPv4(ip)) { return false; }

  const d = ip.split('.');
  return ((((((+d[0])*256)+(+d[1]))*256)+(+d[2]))*256)+(+d[3]);
}

exports.octets_in_string = function (str, oct1, oct2) {
  let oct1_idx;
  let oct2_idx;

  // test the largest of the two octets first
  if (oct2.length >= oct1.length) {
    oct2_idx = str.lastIndexOf(oct2);
    if (oct2_idx === -1) return false;

    oct1_idx = (str.substring(0, oct2_idx) +
            str.substring(oct2_idx + oct2.length)).lastIndexOf(oct1);
    if (oct1_idx === -1) return false;

    return true;  // both were found
  }

  oct1_idx = str.indexOf(oct1);
  if (oct1_idx === -1) return false;

  oct2_idx = (str.substring(0, oct1_idx) +
        str.substring(oct1_idx + oct1.length)).lastIndexOf(oct2);
  if (oct2_idx === -1) return false;

  return true;
}

exports.is_ip_in_str = function (ip, str) {
  if (!str) return false;
  if (!ip) return false;
  if (!net.isIPv4(ip)) return false;   // IPv4 only, for now

  const host_part = (tlds.split_hostname(str,1))[0].toString();
  const octets = ip.split('.');

  // See if the 3rd and 4th octets appear in the string
  if (this.octets_in_string(host_part, octets[2], octets[3])) {
    return true;
  }
  // then the 1st and 2nd octets
  if (this.octets_in_string(host_part, octets[0], octets[1])) {
    return true;
  }

  // Whole IP in hex
  let host_part_copy = host_part;
  const ip_hex = this.dec_to_hex(this.ip_to_long(ip));
  for (let i=0; i<4; i++) {
    const part = host_part_copy.indexOf(ip_hex.substring(i*2, (i*2)+2));
    if (part === -1) break;
    if (i === 3) return true;
    host_part_copy = host_part_copy.substring(0, part) +
            host_part_copy.substring(part+2);
  }
  return false;
}

const re_ipv4 = {
  loopback: /^127\./,
  link_local: /^169\.254\./,

  private10: /^10\./,          // 10/8
  private192: /^192\.168\./,   // 192.168/16
  // 172.16/16 .. 172.31/16
  private172: /^172\.(1[6-9]|2[0-9]|3[01])\./,  // 172.16/12
}

exports.is_private_ipv4 = function (ip) {

  // RFC 1918, reserved as "private" IP space
  if (re_ipv4.private10.test(ip)) return true;
  if (re_ipv4.private192.test(ip)) return true;
  if (re_ipv4.private172.test(ip)) return true;

  return false;
}

exports.on_local_interface = function (ip) {

  if (locallyBoundIPs.length === 0) {
    const ifList = os.networkInterfaces();
    for (const ifName of Object.keys(ifList)) {
      for (const addr of ifList[ifName]) {
        locallyBoundIPs.push(addr.address);
      }
    }
  }

  return locallyBoundIPs.includes(ip);
}

exports.is_local_ip = function (ip) {

  if (this.on_local_interface(ip)) return true;

  if (net.isIPv4(ip)) return this.is_local_ipv4(ip);
  if (net.isIPv6(ip)) return this.is_local_ipv6(ip);

  console.error(`invalid IP address: ${ip}`);
  return false;
}

exports.is_local_ipv4 = function (ip) {
  // 127/8 (loopback)   # RFC 1122
  if (re_ipv4.loopback.test(ip)) return true;

  // link local: 169.254/16 RFC 3927
  if (re_ipv4.link_local.test(ip)) return true;

  return false;
}

const re_ipv6 = {
  loopback:     /^(0{1,4}:){7}0{0,3}1$/,
  link_local:   /^fe80::/i,
  unique_local: /^f(c|d)[a-f0-9]{2}:/i,
}

exports.is_local_ipv6 = function (ip) {
  if (ip === '::1') return true;   // RFC 4291

  // 2 more IPv6 notations for ::1
  // 0:0:0:0:0:0:0:1 or 0000:0000:0000:0000:0000:0000:0000:0001
  if (re_ipv6.loopback.test(ip)) return true;

  // link local: fe80::/10, RFC 4862
  if (re_ipv6.link_local.test(ip)) return true;

  // unique local (fc00::/7)   -> fc00: - fd00:
  if (re_ipv6.unique_local.test(ip)) return true;

  return false;
}

exports.is_private_ip = function (ip) {
  if (net.isIPv4(ip)) return this.is_local_ipv4(ip) || this.is_private_ipv4(ip);
  if (net.isIPv6(ip)) return this.is_local_ipv6(ip);
  return false;
}

// backwards compatibility for non-public modules. Sunset: v3.0
exports.is_rfc1918 = exports.is_private_ip;

exports.is_ip_literal = function (host) {
  return exports.get_ipany_re('^\\[(IPv6:)?','\\]$','').test(host) ? true : false;
}

exports.is_ipv4_literal = function (host) {
  return /^\[(\d{1,3}\.){3}\d{1,3}\]$/.test(host) ? true : false;
}

exports.same_ipv4_network = function (ip, ipList) {
  if (!ipList || !ipList.length) {
    console.error('same_ipv4_network, no ip list!');
    return false;
  }
  if (!net.isIPv4(ip)) {
    console.error('same_ipv4_network, IP is not IPv4!');
    return false;
  }

  const first3 = ip.split('.').slice(0,3).join('.');

  for (let i=0; i < ipList.length; i++) {
    if (!net.isIPv4(ipList[i])) {
      console.error('same_ipv4_network, IP in list is not IPv4!');
      continue;
    }
    if (first3 === ipList[i].split('.').slice(0,3).join('.'))
      return true;
  }
  return false;
}

exports.get_public_ip = function (cb) {
  const nu = this;
  if (nu.public_ip !== undefined) return cb(null, nu.public_ip);  // cache

  // manual config override, for the cases where we can't figure it out
  const smtpIni = exports.config.get('smtp.ini').main;
  if (smtpIni.public_ip) {
    nu.public_ip = smtpIni.public_ip;
    return cb(null, nu.public_ip);
  }

  // Initialise cache value to null to prevent running
  // should we hit a timeout or the module isn't installed.
  nu.public_ip = null;

  try {
    nu.stun = require('vs-stun');
  }
  catch (e) {
    e.install = 'Please install stun: "npm install -g vs-stun"';
    console.error(`${e.msg}\n${e.install}`);
    return cb(e);
  }

  const timeout = 10;
  const timer = setTimeout(() => {
    return cb(new Error('STUN timeout'));
  }, timeout * 1000);

  // Connect to STUN Server
  nu.stun.connect({ host: get_stun_server(), port: 19302 }, (error, socket) => {
    if (timer) clearTimeout(timer);
    if (error) return cb(error);

    socket.close();

    /*          sample socket.stun response
     *
     *  { local: { host: '127.0.0.30', port: 26163 },
     *  public: { host: '50.115.0.94', port: 57345, family: 'IPv4' },
     *  type: 'Full Cone NAT'
     *  }
    */
    if (!socket.stun.public) return cb(new Error('invalid STUN result'));

    nu.public_ip = socket.stun.public.host;
    cb(null, socket.stun.public.host);
  })
}

function get_stun_server () {
  // STUN servers by Google
  const servers = [
    'stun.l.google.com',
    'stun1.l.google.com',
    'stun2.l.google.com',
    'stun3.l.google.com',
    'stun4.l.google.com',
  ];
  return servers[Math.floor(Math.random()*servers.length)];
}

exports.get_ipany_re = function (prefix, suffix, modifier) {
  /* jshint maxlen: false */
  if (prefix === undefined) prefix = '';
  if (suffix === undefined) suffix = '';
  if (modifier === undefined) modifier = 'mg';
  return new RegExp(
    prefix +
        `(` +    // capture group
        `(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-fA-F]{1,4})):){5})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){4})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,1}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,2}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,3}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:[0-9a-fA-F]{1,4})):)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,4}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,5}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,6}(?:(?:[0-9a-fA-F]{1,4})))?::))))` + // complex ipv4 + ipv6
        `)` +    // end capture
        `${suffix}`,
    modifier
  );
}

exports.get_ips_by_host = function (hostname, done) {
  const ips = [];
  const errors = [];

  async.parallel(
    [
      function (iter_done) {
        dns.resolve4(hostname, (err, res) => {
          if (err) {
            errors.push(err);
            return iter_done();
          }
          for (let i=0; i<res.length; i++) {
            ips.push(res[i]);
          }
          iter_done(null, true);
        });
      },
      function (iter_done) {
        dns.resolve6(hostname, (err, res) => {
          if (err) {
            errors.push(err);
            return iter_done();
          }
          for (let j=0; j<res.length; j++) {
            ips.push(res[j]);
          }
          iter_done(null, true);
        });
      },
    ],
    function (err, async_list) {
      // if multiple IPs are included in the iterations, then the async
      // result here will be an array of nested arrays. Not quite what
      // we want. Return the merged ips array.
      done(errors, ips);
    }
  );
}

exports.ipv6_reverse = function (ipv6) {
  ipv6 = ipaddr.parse(ipv6);
  return ipv6.toNormalizedString()
    .split(':')
    .map(function (n) {
      return sprintf('%04x', parseInt(n, 16));
    })
    .join('')
    .split('')
    .reverse()
    .join('.');
}

exports.ipv6_bogus = function (ipv6){
  try {
    const ipCheck = ipaddr.parse(ipv6);
    if (ipCheck.range() !== 'unicast') { return true; }
    return false;
  }
  catch (e) {
    // If we get an error from parsing, return true for bogus.
    console.error(e);
    return true;
  }
}

exports.ip_in_list = function (list, ip) {
  if (list === undefined) return false;

  if (!net.isIP(ip)) return (ip in list); // domain

  for (const string in list) {
    if (string === ip) return true; // exact match

    const cidr = string.split('/');
    const c_net  = cidr[0];

    if (!net.isIP(c_net)) continue;  // bad config entry
    if (net.isIPv4(ip) && net.isIPv6(c_net)) continue;
    if (net.isIPv6(ip) && net.isIPv4(c_net)) continue;

    const c_mask = parseInt(cidr[1], 10) || (net.isIPv6(c_net) ? 128 : 32);

    if (ipaddr.parse(ip).match(ipaddr.parse(c_net), c_mask)) {
      return true;
    }
  }

  return false;
}

exports.get_primary_host_name = function () {
  return exports.config.get('me') || os.hostname();
}

exports.get_mx = function get_mx (domain, cb) {
  let decoded_domain = domain;
  const mxs = [];

  // Possible DNS errors
  // NODATA
  // FORMERR
  // BADRESP
  // NOTFOUND
  // BADNAME
  // TIMEOUT
  // CONNREFUSED
  // NOMEM
  // DESTRUCTION
  // NOTIMP
  // EREFUSED
  // SERVFAIL

  if ( /@/.test(decoded_domain) ) {
    decoded_domain = decoded_domain.split('@').pop();
    // console.log(`\treduced ${domain} to ${decoded_domain}.`)
  }

  if ( /^xn--/.test(decoded_domain) ) {
    decoded_domain = punycode.toASCII(decoded_domain);
    // console.log(`\tdecoded: ${domain} to ${decoded_domain}.`)
  }

  // wrap_mx returns our object with "priority" and "exchange" keys
  let wrap_mx = a => a;

  function process_dns (err, addresses) {
    if (err) {
      // Most likely this is a hostname with no MX record
      // Drop through and we'll get the A record instead.
      switch (err.code) {
        case 'ENODATA':
        case 'ENOTFOUND':
          return 0;
        default:
      }

      cb(err, mxs);
    }
    else if (addresses && addresses.length) {
      for (const addr of addresses) {
        mxs.push(wrap_mx(addr));
      }

      cb(null, mxs);
    }
    else {
      // return zero if we need to keep trying next option
      return 0;
    }
    return 1;
  }

  dns.resolveMx(decoded_domain, (err, addresses) => {
    if (process_dns(err, addresses)) return;

    // if MX lookup failed, we lookup an A record. To do that we change
    // wrap_mx() to return same thing as resolveMx() does.
    wrap_mx = a => ({ priority: 0, exchange: a });

    // IS: IPv6 compatible
    dns.resolve(decoded_domain, (err2, addresses2) => {
      if (process_dns(err2, addresses2)) return;

      err2 = new Error("Found nowhere to deliver to");
      err2.code = 'NOMX';
      cb(err2, mxs);
    })
  })
}
