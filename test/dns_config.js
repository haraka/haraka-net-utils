'use strict'

const assert = require('node:assert')
const { Resolver } = require('node:dns').promises
const { describe, it, beforeEach } = require('node:test')

describe('dns_config', () => {
  let dnsConfig

  beforeEach(() => {
    delete require.cache[require.resolve('../lib/dns_config')]
    dnsConfig = require('../lib/dns_config')
  })

  function mockConfig(dnsSection) {
    dnsConfig.config = {
      get: (filename, type, cb) => {
        if (cb) cb()
        return dnsSection !== undefined ? { dns: dnsSection } : undefined
      },
    }
  }

  it('creates a Resolver with defaults when no config file exists', function () {
    mockConfig(undefined)
    assert.ok(dnsConfig.getDnsResolver() instanceof Resolver)
  })

  it('creates a Resolver with a custom timeout and tries', function () {
    mockConfig({ timeout: 5000, tries: 3 })
    assert.ok(dnsConfig.getDnsResolver() instanceof Resolver)
  })

  it('creates a Resolver when the dns section is absent', function () {
    dnsConfig.config = { get: () => ({ other: {} }) }
    assert.ok(dnsConfig.getDnsResolver() instanceof Resolver)
  })

  it('returns the same instance on repeated calls (singleton)', function () {
    mockConfig({ timeout: 5000, tries: 2 })
    assert.strictEqual(dnsConfig.getDnsResolver(), dnsConfig.getDnsResolver())
  })

  it('registers a reload callback', function () {
    let callbackRegistered = false
    dnsConfig.config = {
      get: (filename, type, cb) => {
        if (cb) callbackRegistered = true
        return { dns: { timeout: 5000, tries: 1 } }
      },
    }
    dnsConfig.getDnsResolver()
    assert.ok(callbackRegistered)
  })
})
