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
    const host = net.isIPv6(this.exchange)
      ? `[${this.exchange}]`
      : this.exchange
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
