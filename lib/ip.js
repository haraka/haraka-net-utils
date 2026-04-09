'use strict'

const net = require('node:net')

const re_ipv4 = {
  loopback: /^127\./,
  link_local: /^169\.254\./,

  private10: /^10\./, // 10/8
  private192: /^192\.168\./, // 192.168/16
  private172: /^172\.(1[6-9]|2[0-9]|3[01])\./, // 172.16/12

  testnet1: /^192\.0\.2\./, // 192.0.2.0/24
  testnet2: /^198\.51\.100\./, // 198.51.100.0/24
  testnet3: /^203\.0\.113\./, // 203.0.113.0/24
}

const re_ipv6 = {
  loopback: /^(0{1,4}:){7}0{0,3}1$/,
  link_local: /^fe80::/i,
  unique_local: /^f(c|d)[a-f0-9]{2}:/i,
}

exports.is_private_ipv4 = function (ip) {
  // RFC 1918, reserved as "private" IP space
  if (re_ipv4.private10.test(ip)) return true
  if (re_ipv4.private192.test(ip)) return true
  if (re_ipv4.private172.test(ip)) return true

  // RFC 5735
  if (re_ipv4.testnet1.test(ip)) return true
  if (re_ipv4.testnet2.test(ip)) return true
  if (re_ipv4.testnet3.test(ip)) return true

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
  if (net.isIPv4(ip))
    return exports.is_local_ipv4(ip) || exports.is_private_ipv4(ip)
  if (net.isIPv6(ip)) return exports.is_local_ipv6(ip)
  return false
}
