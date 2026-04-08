'use strict'

const { Resolver } = require('node:dns').promises

// Export config so it can be overridden by tests or set by main module
exports.config = require('haraka-config')

let dnsResolver = null

function createDnsResolver() {
  const cfg = exports.config.get('net-utils.ini', 'ini') || {}
  return new Resolver({
    timeout: cfg.dns?.timeout || 25000,
    tries: cfg.dns?.tries || 1,
  })
}

exports.getDnsResolver = function () {
  if (!dnsResolver) {
    dnsResolver = createDnsResolver()
    exports.config.get('net-utils.ini', 'ini', () => {
      dnsResolver = createDnsResolver()
    })
  }
  return dnsResolver
}
