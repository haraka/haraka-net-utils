'use strict'

const { Resolver } = require('node:dns').promises
const dns = new Resolver({ timeout: 25000, tries: 1 })
const net = require('node:net')
const os = require('node:os')
const url = require('node:url')

// npm modules
const ipaddr = require('ipaddr.js')
const punycode = require('punycode.js')
const sprintf = require('sprintf-js').sprintf
const tlds = require('haraka-tld')

const locallyBoundIPs = []

// export config, so config base path can be overloaded by tests
exports.config = require('haraka-config')

exports.long_to_ip = function (n) {
  let d = n % 256
  for (let i = 3; i > 0; i--) {
    n = Math.floor(n / 256)
    d = `${n % 256}.${d}`
  }
  return d
}

exports.dec_to_hex = function (d) {
  return d.toString(16)
}

exports.hex_to_dec = function (h) {
  return parseInt(h, 16)
}

exports.ip_to_long = function (ip) {
  if (!net.isIPv4(ip)) return false

  const d = ip.split('.')
  return ((+d[0] * 256 + +d[1]) * 256 + +d[2]) * 256 + +d[3]
}

exports.octets_in_string = function (str, oct1, oct2) {
  let oct1_idx
  let oct2_idx

  // test the largest of the two octets first
  if (oct2.length >= oct1.length) {
    oct2_idx = str.lastIndexOf(oct2)
    if (oct2_idx === -1) return false

    oct1_idx = (
      str.substring(0, oct2_idx) + str.substring(oct2_idx + oct2.length)
    ).lastIndexOf(oct1)
    if (oct1_idx === -1) return false

    return true // both were found
  }

  oct1_idx = str.indexOf(oct1)
  if (oct1_idx === -1) return false

  oct2_idx = (
    str.substring(0, oct1_idx) + str.substring(oct1_idx + oct1.length)
  ).lastIndexOf(oct2)
  if (oct2_idx === -1) return false

  return true
}

exports.is_ip_in_str = function (ip, str) {
  if (!str) return false
  if (!ip) return false
  if (!net.isIPv4(ip)) return false // IPv4 only, for now

  const host_part = tlds.split_hostname(str, 1)[0].toString()
  const octets = ip.split('.')

  // See if the 3rd and 4th octets appear in the string
  if (this.octets_in_string(host_part, octets[2], octets[3])) {
    return true
  }
  // then the 1st and 2nd octets
  if (this.octets_in_string(host_part, octets[0], octets[1])) {
    return true
  }

  // Whole IP in hex
  let host_part_copy = host_part
  const ip_hex = this.dec_to_hex(this.ip_to_long(ip))
  for (let i = 0; i < 4; i++) {
    const part = host_part_copy.indexOf(ip_hex.substring(i * 2, i * 2 + 2))
    if (part === -1) break
    if (i === 3) return true
    host_part_copy =
      host_part_copy.substring(0, part) + host_part_copy.substring(part + 2)
  }
  return false
}

const re_ipv4 = {
  loopback: /^127\./,
  link_local: /^169\.254\./,

  private10: /^10\./, // 10/8
  private192: /^192\.168\./, // 192.168/16
  // 172.16/16 .. 172.31/16
  private172: /^172\.(1[6-9]|2[0-9]|3[01])\./, // 172.16/12

  // RFC 5735
  testnet1: /^192\.0\.2\./, // 192.0.2.0/24
  testnet2: /^198\.51\.100\./, // 198.51.100.0/24
  testnet3: /^203\.0\.113\./, // 203.0.113.0/24
}

exports.is_private_ipv4 = function (ip) {
  // RFC 1918, reserved as "private" IP space
  if (re_ipv4.private10.test(ip)) return true
  if (re_ipv4.private192.test(ip)) return true
  if (re_ipv4.private172.test(ip)) return true

  if (re_ipv4.testnet1.test(ip)) return true
  if (re_ipv4.testnet2.test(ip)) return true
  if (re_ipv4.testnet3.test(ip)) return true

  return false
}

exports.on_local_interface = function (ip) {
  if (locallyBoundIPs.length === 0) {
    const ifList = os.networkInterfaces()
    for (const ifName of Object.keys(ifList)) {
      for (const addr of ifList[ifName]) {
        locallyBoundIPs.push(addr.address)
      }
    }
  }

  return locallyBoundIPs.includes(ip)
}

exports.is_local_host = async function (dst_host) {
  // Is the destination hostname/IP delivered to a hostname or IP
  // that's local to _this_ mail server?
  const local_ips = []
  const dest_ips = []

  try {
    const public_ip = await this.get_public_ip()
    if (public_ip) local_ips.push(public_ip)

    const local_hostname = this.get_primary_host_name()
    local_ips.push(...(await this.get_ips_by_host(local_hostname)))

    if (net.isIP(dst_host)) {
      // an IP address
      dest_ips.push(dst_host)
    } else {
      // a hostname
      if (dst_host === local_hostname) return true
      dest_ips.push(...(await this.get_ips_by_host(dst_host)))
    }
  } catch (e) {
    // console.error(e)
    return false
  }

  for (const ip of dest_ips) {
    if (this.is_local_ip(ip)) return true
    if (local_ips.includes(ip)) return true
  }
  return false
}

exports.is_local_ip = function (ip) {
  if (this.on_local_interface(ip)) return true

  if (net.isIPv4(ip)) return this.is_local_ipv4(ip)
  if (net.isIPv6(ip)) return this.is_local_ipv6(ip)

  // console.error(`invalid IP address: ${ip}`);
  return false
}

exports.is_local_ipv4 = function (ip) {
  if ('0.0.0.0' === ip) return true // RFC 5735

  // 127/8 (loopback)   # RFC 1122
  if (re_ipv4.loopback.test(ip)) return true

  // link local: 169.254/16 RFC 3927
  if (re_ipv4.link_local.test(ip)) return true

  return false
}

const re_ipv6 = {
  loopback: /^(0{1,4}:){7}0{0,3}1$/,
  link_local: /^fe80::/i,
  unique_local: /^f(c|d)[a-f0-9]{2}:/i,
}

exports.is_local_ipv6 = function (ip) {
  if (ip === '::') return true // RFC 5735
  if (ip === '::1') return true // RFC 4291

  // 2 more IPv6 notations for ::1
  // 0:0:0:0:0:0:0:1 or 0000:0000:0000:0000:0000:0000:0000:0001
  if (re_ipv6.loopback.test(ip)) return true

  // link local: fe80::/10, RFC 4862
  if (re_ipv6.link_local.test(ip)) return true

  // unique local (fc00::/7)   -> fc00: - fd00:
  if (re_ipv6.unique_local.test(ip)) return true

  return false
}

exports.is_private_ip = function (ip) {
  if (net.isIPv4(ip)) return this.is_local_ipv4(ip) || this.is_private_ipv4(ip)
  if (net.isIPv6(ip)) return this.is_local_ipv6(ip)
  return false
}

// backwards compatibility for non-public modules. Sunset: v3.0
exports.is_rfc1918 = exports.is_private_ip

exports.is_ip_literal = function (host) {
  return exports.get_ipany_re('^\\[(IPv6:)?', '\\]$', '').test(host)
    ? true
    : false
}

exports.is_ipv4_literal = function (host) {
  return /^\[(\d{1,3}\.){3}\d{1,3}\]$/.test(host) ? true : false
}

exports.same_ipv4_network = function (ip, ipList) {
  if (!ipList || !ipList.length) {
    console.error('same_ipv4_network, no ip list!')
    return false
  }
  if (!net.isIPv4(ip)) {
    console.error('same_ipv4_network, IP is not IPv4!')
    return false
  }

  const first3 = ip.split('.').slice(0, 3).join('.')

  for (let i = 0; i < ipList.length; i++) {
    if (!net.isIPv4(ipList[i])) {
      console.error('same_ipv4_network, IP in list is not IPv4!')
      continue
    }
    if (first3 === ipList[i].split('.').slice(0, 3).join('.')) return true
  }
  return false
}

exports.get_public_ip_async = async function () {
  if (this.public_ip !== undefined) return this.public_ip // cache

  // manual config override, for the cases where we can't figure it out
  const smtpIni = exports.config.get('smtp.ini').main
  if (smtpIni.public_ip) {
    this.public_ip = smtpIni.public_ip
    return this.public_ip
  }

  // Initialise cache value to null to prevent running
  // should we hit a timeout or the module isn't installed.
  this.public_ip = null

  try {
    this.stun = require('@msimerson/stun')
  } catch (e) {
    e.install = 'Please install stun: "npm install -g stun"'
    console.error(`${e.msg}\n${e.install}`)
    return
  }

  const timeout = 10
  const timer = setTimeout(() => {
    return new Error('STUN timeout')
  }, timeout * 1000)

  // Connect to STUN Server
  const res = await this.stun.request(get_stun_server(), {
    maxTimeout: (timeout - 1) * 1000,
  })
  this.public_ip = res.getXorAddress().address
  clearTimeout(timer)
  return this.public_ip
}

exports.get_public_ip = async function (cb) {
  if (!cb) return exports.get_public_ip_async()

  if (this.public_ip !== undefined) return cb(null, this.public_ip) // cache

  // manual config override, for the cases where we can't figure it out
  const smtpIni = exports.config.get('smtp.ini').main
  if (smtpIni.public_ip) {
    this.public_ip = smtpIni.public_ip
    return cb(null, this.public_ip)
  }

  // Initialise cache value to null to prevent running
  // should we hit a timeout or the module isn't installed.
  this.public_ip = null

  try {
    this.stun = require('@msimerson/stun')
  } catch (e) {
    e.install = 'Please install stun: "npm install -g stun"'
    console.error(`${e.msg}\n${e.install}`)
    return cb(e)
  }

  const timeout = 10
  const timer = setTimeout(() => {
    return cb(new Error('STUN timeout'))
  }, timeout * 1000)

  // Connect to STUN Server
  this.stun.request(
    get_stun_server(),
    { maxTimeout: (timeout - 1) * 1000 },
    (error, res) => {
      if (timer) clearTimeout(timer)
      if (error) return cb(error)

      this.public_ip = res.getXorAddress().address
      cb(null, this.public_ip)
    },
  )
}

function get_stun_server() {
  const servers = [
    'stun.l.google.com:19302',
    'stun1.l.google.com:19302',
    'stun2.l.google.com:19302',
    'stun3.l.google.com:19302',
    'stun4.l.google.com:19302',
  ]
  return servers[Math.floor(Math.random() * servers.length)]
}

exports.get_ipany_re = function (prefix = '', suffix = '', modifier = 'mg') {
  return new RegExp(
    prefix +
      `(` + // capture group
      `(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-fA-F]{1,4})):){5})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){4})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,1}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,2}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,3}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:[0-9a-fA-F]{1,4})):)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,4}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,5}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,6}(?:(?:[0-9a-fA-F]{1,4})))?::))))` + // complex ipv4 + ipv6
      `)` + // end capture
      `${suffix}`,
    modifier,
  )
}

exports.get_ips_by_host = function (hostname, done) {
  const ips = new Set()
  const errors = []

  return Promise.allSettled([
    dns.resolve6(hostname),
    dns.resolve4(hostname),
  ]).then((res) => {
    res.filter((a) => a.status === 'rejected').map((a) => errors.push(a.reason))

    res
      .filter((a) => a.status === 'fulfilled')
      .map((a) => a.value.map((ip) => ips.add(ip)))

    if (done) done(errors, Array.from(ips))
    return Array.from(ips)
  })
}

exports.ipv6_reverse = function (ipv6) {
  ipv6 = ipaddr.parse(ipv6)
  return ipv6
    .toNormalizedString()
    .split(':')
    .map(function (n) {
      return sprintf('%04x', parseInt(n, 16))
    })
    .join('')
    .split('')
    .reverse()
    .join('.')
}

exports.ipv6_bogus = function (ipv6) {
  try {
    const ipCheck = ipaddr.parse(ipv6)
    if (ipCheck.range() !== 'unicast') return true
    return false
  } catch (e) {
    // If we get an error from parsing, return true for bogus.
    console.error(e)
    return true
  }
}

exports.ip_in_list = function (list, ip) {
  if (list === undefined) return false

  const isHostname = !net.isIP(ip)
  const isArray = Array.isArray(list)

  // Quick lookup
  if (!isArray) {
    if (ip in list) return true // domain or literal IP
    if (isHostname) return false // skip CIDR match
  }

  // Iterate: arrays and CIDR matches
  for (let item in list) {
    if (isArray) {
      item = list[item] // item is index
      if (item === ip) return true // exact match
    }
    if (isHostname) continue // skip CIDR match

    const cidr = item.split('/')
    const c_net = cidr[0]

    if (!net.isIP(c_net)) continue // bad config entry
    if (net.isIPv4(ip) && net.isIPv6(c_net)) continue
    if (net.isIPv6(ip) && net.isIPv4(c_net)) continue

    const c_mask = parseInt(cidr[1], 10) || (net.isIPv6(c_net) ? 128 : 32)

    if (ipaddr.parse(ip).match(ipaddr.parse(c_net), c_mask)) {
      return true
    }
  }

  return false
}

exports.get_primary_host_name = function () {
  return exports.config.get('me') || os.hostname()
}

function normalizeDomain(raw_domain) {
  let domain = raw_domain

  if (/@/.test(domain)) {
    domain = domain.split('@').pop()
    // console.log(`\treduced ${raw_domain} to ${domain}.`)
  }

  if (/^xn--/.test(domain)) {
    // is punycode IDN with ACE, ASCII Compatible Encoding
  } else if (domain !== punycode.toASCII(domain)) {
    domain = punycode.toASCII(domain)
    console.log(`\tACE encoded '${raw_domain}' to '${domain}'`)
  }

  return domain
}

function fatal_mx_err(err) {
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

  switch (err.code) {
    case 'ENODATA':
    case 'ENOTFOUND':
      // likely a hostname with no MX record, drop through
      return false
    default:
      return err
  }
}

exports.get_mx = async (raw_domain, cb) => {
  const domain = normalizeDomain(raw_domain)

  try {
    let exchanges = await dns.resolveMx(domain)
    if (exchanges && exchanges.length) {
      exchanges = exchanges.map((e) => new HarakaMx(e, domain))
      if (cb) return cb(null, exchanges)
      return exchanges
    }
    // no MX record(s), fall through
  } catch (err) {
    if (fatal_mx_err(err)) {
      if (cb) return cb(err, [])
      throw err
    }
    // non-terminal DNS failure, fall through
  }

  const exchanges = await this.get_implicit_mx(domain)
  if (cb) return cb(null, exchanges)
  return exchanges
}

exports.get_implicit_mx = async (domain) => {
  // console.log(`No MX for ${domain}, trying AAAA & A records`)

  const promises = [dns.resolve6(domain), dns.resolve4(domain)]
  const r = await Promise.allSettled(promises)

  return r
    .filter((a) => a.status === 'fulfilled')
    .flatMap((a) => a.value.map((ip) => new HarakaMx(ip, domain)))
}

exports.resolve_mx_hosts = async (mxes) => {
  // for the given list of MX exchanges, resolve the hostnames to IPs
  const promises = []

  for (const mx of mxes) {
    if (!mx.exchange) {
      promises.push(mx)
      continue
    }

    if (net.isIP(mx.exchange)) {
      promises.push(mx) // already resolved
      continue
    }

    // resolve AAAA and A since mx.exchange is a hostname
    promises.push(
      dns
        .resolve6(mx.exchange)
        .then((ips) =>
          ips.map((ip) => ({ ...mx, exchange: ip, from_dns: mx.exchange })),
        ),
    )

    promises.push(
      dns
        .resolve4(mx.exchange)
        .then((ips) =>
          ips.map((ip) => ({ ...mx, exchange: ip, from_dns: mx.exchange })),
        ),
    )
  }

  const settled = await Promise.allSettled(promises)

  return settled.filter((s) => s.status === 'fulfilled').flatMap((s) => s.value)
}

class HarakaMx {
  constructor(obj = {}, domain) {
    switch (typeof obj) {
      case 'string':
        /mtp:\/\//.test(obj) ? this.fromUrl(obj) : this.fromString(obj)
        break
      case 'object':
        this.fromObject(obj)
        break
    }

    if (this.priority === undefined) this.priority = 0
    if (domain && this.from_dns === undefined) {
      this.from_dns = domain.toLowerCase()
    }
  }

  fromObject(obj) {
    for (const prop of [
      'exchange',
      'priority',
      'port',
      'bind',
      'bind_helo',
      'using_lmtp',
      'auth_user',
      'auth_pass',
      'auth_type',
      'from_dns',
    ]) {
      if (obj[prop] !== undefined) this[prop] = obj[prop]
    }
  }

  fromString(str) {
    const matches = /^\[?(.*?)\]?(?::(24|25|465|587|\d{4,5}))?$/.exec(str)
    if (matches) {
      this.exchange = matches[1].toLowerCase()
      if (matches[2]) this.port = parseInt(matches[2])
    } else {
      this.exchange = str
    }
  }

  fromUrl(str) {
    const dest = new url.URL(str)

    switch (dest.protocol) {
      case 'smtp:':
        if (!dest.port) dest.port = 25
        break
      case 'lmtp:':
        this.using_lmtp = true
        if (!dest.port) dest.port = 24
        break
    }

    if (dest.hostname) this.exchange = dest.hostname.toLowerCase()
    if (dest.port) this.port = parseInt(dest.port)
    if (dest.username) this.auth_user = dest.username
    if (dest.password) this.auth_pass = dest.password
  }

  toUrl() {
    const proto = this.using_lmtp ? 'lmtp://' : 'smtp://'
    const auth = this.auth_user ? `${this.auth_user}:****@` : ''
    const host = net.isIPv6(this.exchange)
      ? `[${this.exchange}]`
      : this.exchange
    const port = this.port ? this.port : proto === 'lmtp://' ? 24 : 25
    return new url.URL(`${proto}${auth}${host}:${port}`)
  }

  toString() {
    const from_dns = this.from_dns ? ` (from ${this.from_dns})` : ''
    return `MX ${this.priority} ${this.toUrl()}${from_dns}`
  }
}

/*
 * A string of one of the following formats:
 * hostname
 * hostname:port
 * ipaddress
 * ipaddress:port
 */

exports.HarakaMx = HarakaMx
