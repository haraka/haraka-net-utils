'use strict'

const net = require('node:net')
const url = require('node:url')

class HarakaMx {
  constructor(obj = {}, domain) {
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

module.exports = HarakaMx
