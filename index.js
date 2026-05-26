'use strict'

const dns = require('./lib/dns_config').getDnsResolver()
const net = require('node:net')
const os = require('node:os')

// npm modules
const ipaddr = require('ipaddr.js')
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
  if (exports.octets_in_string(host_part, octets[2], octets[3])) {
    return true
  }
  // then the 1st and 2nd octets
  if (exports.octets_in_string(host_part, octets[0], octets[1])) {
    return true
  }

  // Whole IP in hex
  let host_part_copy = host_part
  const ip_hex = exports.dec_to_hex(exports.ip_to_long(ip))
  for (let i = 0; i < 4; i++) {
    const part = host_part_copy.indexOf(ip_hex.substring(i * 2, i * 2 + 2))
    if (part === -1) break
    if (i === 3) return true
    host_part_copy =
      host_part_copy.substring(0, part) + host_part_copy.substring(part + 2)
  }
  return false
}

const {
  is_private_ipv4,
  is_local_ipv4,
  is_local_ipv6,
  is_private_ip,
} = require('./lib/ip')

exports.is_private_ipv4 = is_private_ipv4
exports.is_local_ipv4 = is_local_ipv4
exports.is_local_ipv6 = is_local_ipv6
exports.is_private_ip = is_private_ip

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
    const public_ip = await exports.get_public_ip()
    if (public_ip) local_ips.push(public_ip)

    const local_hostname = exports.get_primary_host_name()
    local_ips.push(...(await exports.get_ips_by_host(local_hostname)))

    if (net.isIP(dst_host)) {
      // an IP address
      dest_ips.push(dst_host)
    } else {
      // a hostname
      if (dst_host === local_hostname) return true
      dest_ips.push(...(await exports.get_ips_by_host(dst_host)))
    }
  } catch (ignore) {
    // console.error(ignore)
    return false
  }

  for (const ip of dest_ips) {
    if (exports.is_local_ip(ip)) return true
    if (local_ips.includes(ip)) return true
  }
  return false
}

exports.is_local_ip = function (ip) {
  if (exports.on_local_interface(ip)) return true

  if (net.isIPv4(ip)) return is_local_ipv4(ip)
  if (net.isIPv6(ip)) return is_local_ipv6(ip)

  // console.error(`invalid IP address: ${ip}`);
  return false
}

// backwards compatibility for non-public modules. Sunset: v3.0
exports.is_rfc1918 = exports.is_private_ip

exports.is_ip_literal = function (host) {
  return exports.get_ipany_re('^\\[(IPv6:)?', '\\]$', '').test(host)
}

exports.is_ipv4_literal = function (host) {
  return /^\[(\d{1,3}\.){3}\d{1,3}\]$/.test(host)
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

  for (const listIp of ipList) {
    if (!net.isIPv4(listIp)) {
      console.error('same_ipv4_network, IP in list is not IPv4!')
      continue
    }
    if (first3 === listIp.split('.').slice(0, 3).join('.')) return true
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
    for (const a of res) {
      if (a.status === 'rejected') errors.push(a.reason)
      else for (const ip of a.value) ips.add(ip)
    }

    if (done) done(errors, Array.from(ips))
    return Array.from(ips)
  })
}

exports.ipv6_reverse = function (ipv6) {
  ipv6 = ipaddr.parse(ipv6)
  return ipv6
    .toNormalizedString()
    .split(':')
    .map((n) => parseInt(n, 16).toString(16).padStart(4, '0'))
    .join('')
    .split('')
    .reverse()
    .join('.')
}

exports.ipv6_bogus = function (ipv6) {
  try {
    return ipaddr.parse(ipv6).range() !== 'unicast'
  } catch (e) {
    // If we get an error from parsing, return true for bogus.
    console.error(`ipv6_bogus(${ipv6}): ${e.message}`)
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
  for (const item of isArray ? list : Object.keys(list)) {
    if (isArray && item === ip) return true // exact match
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

exports.normalize_ip = function (ip) {
  if (!net.isIP(ip)) return null
  return ipaddr.process(ip).toString()
}

exports.get_primary_host_name = function () {
  return exports.config.get('me') || os.hostname()
}

for (const l of ['get_mx', 'get_implicit_mx', 'resolve_mx_hosts']) {
  exports[l] = require('./lib/get_mx')[l]
}

exports.get_public_ip = require('./lib/get_public_ip').get_public_ip

exports.HarakaMx = require('./lib/HarakaMx')

const MAX_LINE_LENGTH = 4 * 1024 * 1024 // 4 MB; defence against DoS via lines without newlines

exports.add_line_processor = (socket) => {
  const line_regexp = /^([^\n]*\n)/
  let current_data = ''

  socket.on('data', (data) => {
    current_data += data

    if (current_data.length > MAX_LINE_LENGTH) {
      socket.emit(
        'error',
        new Error(`Line length exceeded ${MAX_LINE_LENGTH} bytes`),
      )
      current_data = ''
      return
    }

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

exports.parse_proxy_line = function (line) {
  const proxyLine = line?.toString().replace(/\r?\n$/, '')
  const match = /^(?:PROXY )?(TCP4|TCP6|UNKNOWN) (\S+) (\S+) (\d+) (\d+)$/.exec(proxyLine)
  if (!match) return null

  const proto = match[1]
  const src_ip = match[2]
  const dst_ip = match[3]
  const src_port = match[4]
  const dst_port = match[5]

  if (proto === 'TCP4' && ipaddr.IPv4.isValid(src_ip) && ipaddr.IPv4.isValid(dst_ip)) {
    return { type: 'haproxy', proto, src_ip, src_port, dst_ip, dst_port }
  }

  if (proto === 'TCP6' && ipaddr.IPv6.isValid(src_ip) && ipaddr.IPv6.isValid(dst_ip)) {
    return { type: 'haproxy', proto, src_ip, src_port, dst_ip, dst_port }
  }

  return null
}

exports.is_haproxy_allowed = function (ip) {
  const haproxyConfig = exports.config.get('connection.ini', {
    booleans: ['+haproxy.enabled'],
  })?.haproxy ?? {}
  const haproxyEnabled = haproxyConfig.enabled !== false
  const haproxy_hosts_ipv4 = []
  const haproxy_hosts_ipv6 = []

  if (!haproxyEnabled) return false

  const normalized_ip = exports.normalize_ip(ip)
  if (!normalized_ip) return false

  for (const host of haproxyConfig.hosts ?? []) {
    if (!host) continue
    if (net.isIPv6(host.split('/')[0])) {
      haproxy_hosts_ipv6.push([ipaddr.IPv6.parse(host.split('/')[0]), parseInt(host.split('/')[1] || 64)])
    } else {
      haproxy_hosts_ipv4.push([ipaddr.IPv4.parse(host.split('/')[0]), parseInt(host.split('/')[1] || 32)])
    }
  }

  const ha_list = net.isIPv6(normalized_ip) ? haproxy_hosts_ipv6 : haproxy_hosts_ipv4
  return ha_list.some((element) => ipaddr.parse(normalized_ip).match(element[0], element[1]))
}
