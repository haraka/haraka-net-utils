'use strict'

const { Resolver } = require('node:dns').promises
const dns = new Resolver({ timeout: 25000, tries: 1 })
const net = require('node:net')
const os = require('node:os')

// npm modules
const ipaddr = require('ipaddr.js')
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
  } catch (ignore) {
    // console.error(ignore)
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

for (const l of ['get_mx', 'get_implicit_mx', 'resolve_mx_hosts']) {
  exports[l] = require('./lib/get_mx')[l]
}

exports.get_public_ip = require('./lib/get_public_ip').get_public_ip

exports.get_public_ip_async = require('./lib/get_public_ip').get_public_ip_async

exports.HarakaMx = require('./lib/HarakaMx')

exports.add_line_processor = (socket) => {
  const line_regexp = /^([^\n]*\n)/ // utils.line_regexp
  let current_data = ''

  socket.on('data', (data) => {
    current_data += data
    let results
    while ((results = line_regexp.exec(current_data))) {
      const this_line = results[1]
      current_data = current_data.slice(this_line.length)
      socket.emit('line', this_line)
    }
  })

  socket.on('end', () => {
    if (current_data.length) {
      socket.emit('line', current_data)
    }
    current_data = ''
  })
}
