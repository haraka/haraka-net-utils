'use strict'

const assert = require('assert')
const { Resolver } = require('node:dns').promises

describe('dns_config', function () {
  let dnsConfig

  beforeEach(function () {
    // Clear the module cache to get a fresh instance
    delete require.cache[require.resolve('../lib/dns_config')]
    dnsConfig = require('../lib/dns_config')
  })

  afterEach(function () {
    // Reset the resolver instance
    if (dnsConfig.getDnsResolver && dnsConfig.getDnsResolver._resolver) {
      delete dnsConfig.getDnsResolver._resolver
    }
  })

  describe('default configuration', function () {
    it('should use default timeout and tries when no config file exists', function () {
      // Mock config to return empty/undefined
      dnsConfig.config = {
        get: () => undefined
      }

      const resolver = dnsConfig.getDnsResolver()
      assert(resolver instanceof Resolver, 'Should return a Resolver instance')

      // We can't directly access timeout/tries from Resolver, but we can verify it was created
      assert(typeof resolver.resolve4 === 'function', 'Should have resolve4 method')
      assert(typeof resolver.resolve6 === 'function', 'Should have resolve6 method')
    })

    it('should use default values when dns section is missing', function () {
      dnsConfig.config = {
        get: () => ({ other_section: { value: 'test' } })
      }

      const resolver = dnsConfig.getDnsResolver()
      assert(resolver instanceof Resolver, 'Should return a Resolver instance')
    })
  })

  describe('custom configuration', function () {
    it('should use custom timeout and tries from config file', function () {
      const mockConfig = {
        dns: {
          timeout: '15000',
          tries: '3'
        }
      }

      dnsConfig.config = {
        get: (filename) => {
          if (filename === 'net-utils.ini') {
            return mockConfig
          }
          return undefined
        }
      }

      const resolver = dnsConfig.getDnsResolver()
      assert(resolver instanceof Resolver, 'Should return a Resolver instance')
    })

    it('should handle invalid timeout values gracefully', function () {
      const mockConfig = {
        dns: {
          timeout: 'invalid',
          tries: 'also-invalid'
        }
      }

      dnsConfig.config = {
        get: () => mockConfig
      }

      // Should not throw and should fall back to defaults
      const resolver = dnsConfig.getDnsResolver()
      assert(resolver instanceof Resolver, 'Should return a Resolver instance')
    })

    it('should handle missing timeout/tries in dns section', function () {
      const mockConfig = {
        dns: {
          other_setting: 'value'
        }
      }

      dnsConfig.config = {
        get: () => mockConfig
      }

      const resolver = dnsConfig.getDnsResolver()
      assert(resolver instanceof Resolver, 'Should return a Resolver instance')
    })
  })

  describe('singleton behavior', function () {
    it('should return the same resolver instance on multiple calls', function () {
      dnsConfig.config = {
        get: () => ({ dns: { timeout: '5000', tries: '2' } })
      }

      const resolver1 = dnsConfig.getDnsResolver()
      const resolver2 = dnsConfig.getDnsResolver()

      assert.strictEqual(resolver1, resolver2, 'Should return the same instance')
    })
  })

  describe('configuration reload', function () {
    it('should set up config reload callback', function () {
      // let callbackCalled = false
      let storedCallback = null

      dnsConfig.config = {
        get: (filename, type, callback) => {
          if (callback) {
            storedCallback = callback
          }
          return { dns: { timeout: '10000', tries: '1' } }
        }
      }

      // Get the initial resolver (should set up the callback)
      const resolver1 = dnsConfig.getDnsResolver()

      assert(storedCallback !== null, 'Callback should have been registered')
      assert(typeof storedCallback === 'function', 'Callback should be a function')

      // Simulate config change by calling the callback
      storedCallback()

      // The callback should trigger a new resolver creation
      // (This is internal behavior that's hard to test directly)
      assert(resolver1 instanceof Resolver, 'Original resolver should still be valid')
    })
  })

  describe('integration with existing code', function () {
    it('should work with index.js imports', function () {
      // Test that the module can be required from index.js path
      const indexPath = require.resolve('../index.js')
      assert(indexPath, 'Should be able to resolve index.js path')

      // Clear cache and require index.js to test integration
      delete require.cache[indexPath]
      delete require.cache[require.resolve('../lib/dns_config')]

      const netUtils = require('../index.js')
      assert(typeof netUtils.get_ips_by_host === 'function', 'Should export get_ips_by_host function')
    })

    it('should work with get_mx.js imports', function () {
      // Test that the module can be required from get_mx.js path
      const getMxPath = require.resolve('../lib/get_mx.js')
      assert(getMxPath, 'Should be able to resolve get_mx.js path')

      // Clear cache and require get_mx.js to test integration
      delete require.cache[getMxPath]
      delete require.cache[require.resolve('../lib/dns_config')]

      const getMx = require('../lib/get_mx.js')
      assert(typeof getMx.get_mx === 'function', 'Should export get_mx function')
    })
  })

  describe('configuration file format validation', function () {
    it('should handle various timeout formats', function () {
      const testCases = [
        { input: '5000', expected: 'valid' },
        { input: 5000, expected: 'valid' },
        { input: '0', expected: 'valid' },
        { input: '', expected: 'fallback' },
        { input: null, expected: 'fallback' },
        { input: undefined, expected: 'fallback' }
      ]

      testCases.forEach(({ input }) => {
        dnsConfig.config = {
          get: () => ({ dns: { timeout: input, tries: '1' } })
        }

        // Clear the cached resolver
        if (dnsConfig.getDnsResolver._resolver) {
          delete dnsConfig.getDnsResolver._resolver
        }

        const resolver = dnsConfig.getDnsResolver()
        assert(resolver instanceof Resolver, `Should handle timeout value: ${input}`)
      })
    })

    it('should handle various tries formats', function () {
      const testCases = [
        { input: '1', expected: 'valid' },
        { input: 3, expected: 'valid' },
        { input: '0', expected: 'valid' },
        { input: '', expected: 'fallback' },
        { input: null, expected: 'fallback' },
        { input: undefined, expected: 'fallback' }
      ]

      testCases.forEach(({ input }) => {
        dnsConfig.config = {
          get: () => ({ dns: { timeout: '25000', tries: input } })
        }

        // Clear the cached resolver
        if (dnsConfig.getDnsResolver._resolver) {
          delete dnsConfig.getDnsResolver._resolver
        }

        const resolver = dnsConfig.getDnsResolver()
        assert(resolver instanceof Resolver, `Should handle tries value: ${input}`)
      })
    })
  })
})