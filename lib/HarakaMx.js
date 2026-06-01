'use strict'

const net = require('node:net')
const os = require('node:os')
const url = require('node:url')

const config = require('haraka-config')

class HarakaMx {
  constructor(obj = {}, domain) {
    if (obj instanceof HarakaMx) return obj

    switch (typeof obj) {
      case 'string':
        ;/mtp:\/\//.test(obj) ? this.fromUrl(obj) : this.fromString(obj)
        break
      case 'object':
        this.fromObject(obj)
        break
    }

    if (this.priority === undefined) this.priority = 0

    if (domain && this.from_dns === undefined) {
      this.from_dns = domain.toLowerCase()
    }

    if (process.env.NODE_ENV !== 'test') {
      if (this.bind_helo === undefined) {
        this.bind_helo = config.get('me') || os.hostname()
      }
    }
  }

  fromObject(obj) {
    for (const prop of [
      'exchange',
      'path',
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
    // Bracketed: [host] or [host]:port
    if (str.startsWith('[')) {
      const end = str.indexOf(']')
      if (end > 0) {
        this.exchange = str.slice(1, end).toLowerCase()
        if (str[end + 1] === ':') {
          const port = parseInt(str.slice(end + 2), 10)
          if (port >= 1 && port <= 65535) this.port = port
        }
        return
      }
    }

    // Unbracketed but a valid IPv6 literal: the whole string is the host
    if (net.isIPv6(str)) {
      this.exchange = str.toLowerCase()
      return
    }

    // Hostname or IPv4, optionally followed by :port
    const colon = str.lastIndexOf(':')
    if (colon > 0 && /^\d+$/.test(str.slice(colon + 1))) {
      const port = parseInt(str.slice(colon + 1), 10)
      if (port >= 1 && port <= 65535) {
        this.exchange = str.slice(0, colon).toLowerCase()
        this.port = port
        return
      }
    }

    this.exchange = str.toLowerCase()
  }

  fromUrl(str) {
    const dest = new url.URL(str)

    switch (dest.protocol) {
      case 'smtp:':
        break
      case 'lmtp:':
        this.using_lmtp = true
        break
    }

    if (dest.hostname) this.exchange = dest.hostname.toLowerCase()
    if (dest.port) this.port = parseInt(dest.port)
    if (dest.username) this.auth_user = dest.username
    if (dest.password) this.auth_pass = dest.password
  }

  toUrl() {
    const host = net.isIPv6(this.exchange) ? `[${this.exchange}]` : this.exchange
    if (this.path) {
      return new url.URL(`file://${host || 'localhost'}${this.path}`).href
    }
    const proto = this.using_lmtp ? 'lmtp://' : 'smtp://'
    const auth = this.auth_user ? `${this.auth_user}:****@` : ''
    const port = this.port ? `:${this.port}` : ''
    return new url.URL(`${proto}${auth}${host}${port}`).href
  }

  toString() {
    const from_dns = this.from_dns ? ` (via DNS)` : ''
    return `MX ${this.priority} ${this.toUrl()}${from_dns}`
  }
}

module.exports = HarakaMx
