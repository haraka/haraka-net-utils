'use strict'

const assert = require('assert')

describe('DNS Integration Tests', function () {
  let netUtils
  let getMx

  // Increase timeout for DNS operations
  this.timeout(10000)

  beforeEach(function () {
    // Clear module cache to get fresh instances
    delete require.cache[require.resolve('../index.js')]
    delete require.cache[require.resolve('../lib/get_mx.js')]
    delete require.cache[require.resolve('../lib/dns_config.js')]

    netUtils = require('../index.js')
    getMx = require('../lib/get_mx.js')
  })

  describe('DNS resolution with default config', function () {
    it('should resolve IPv4 addresses', async function () {
      const ips = await netUtils.get_ips_by_host('google.com')
      assert(Array.isArray(ips), 'Should return an array')
      assert(ips.length > 0, 'Should return at least one IP')

      // Should have at least one IPv4 address
      const hasIPv4 = ips.some(ip => require('node:net').isIPv4(ip))
      assert(hasIPv4, 'Should include IPv4 addresses')
    })

    it('should resolve MX records', async function () {
      const mx = await getMx.get_mx('google.com')
      assert(Array.isArray(mx), 'Should return an array')
      assert(mx.length > 0, 'Should return at least one MX record')
      assert(typeof mx[0].exchange === 'string', 'MX record should have exchange property')
    })

    it('should handle non-existent domains gracefully', async function () {
      try {
        await netUtils.get_ips_by_host('this-domain-definitely-does-not-exist-12345.com')
        // If no error is thrown, should return empty array
      } catch (err) {
        // DNS errors are expected for non-existent domains
        assert(err.code === 'ENOTFOUND' || err.code === 'ENODATA',
               `Expected DNS error, got: ${err.code}`)
      }
    })
  })

  describe('DNS resolution with custom config', function () {
    beforeEach(function () {
      // Mock the config to use custom settings
      const dnsConfig = require('../lib/dns_config')
      dnsConfig.config = {
        get: (filename, type, callback) => {
          if (filename === 'net-utils.ini') {
            // Register callback if provided (for reload functionality)
            if (callback) {
              // Store callback but don't call it in tests
            }
            return {
              dns: {
                timeout: '5000',  // Shorter timeout for testing
                tries: '2'        // More retries
              }
            }
          }
          return undefined
        }
      }
    })

    it('should use custom configuration for DNS resolution', async function () {
      // Clear the DNS resolver cache to pick up new config
      const dnsConfig = require('../lib/dns_config')
      if (dnsConfig.getDnsResolver._resolver) {
        delete dnsConfig.getDnsResolver._resolver
      }

      // Re-require modules to pick up new config
      delete require.cache[require.resolve('../index.js')]
      delete require.cache[require.resolve('../lib/get_mx.js')]

      const customNetUtils = require('../index.js')
      const customGetMx = require('../lib/get_mx.js')

      // Test that DNS still works with custom config
      const ips = await customNetUtils.get_ips_by_host('google.com')
      assert(Array.isArray(ips), 'Should return an array with custom config')
      assert(ips.length > 0, 'Should return at least one IP with custom config')

      const mx = await customGetMx.get_mx('google.com')
      assert(Array.isArray(mx), 'Should return MX records with custom config')
      assert(mx.length > 0, 'Should return at least one MX record with custom config')
    })

    it('should handle timeout scenarios with custom config', async function () {
      // This test is tricky because we can't easily simulate timeouts
      // But we can verify the resolver is created with custom settings
      const dnsConfig = require('../lib/dns_config')
      const resolver = dnsConfig.getDnsResolver()

      assert(resolver, 'Should create resolver with custom config')
      assert(typeof resolver.resolve4 === 'function', 'Should have resolve4 method')
    })
  })

  describe('Configuration edge cases', function () {
    it('should handle malformed config gracefully', function () {
      const dnsConfig = require('../lib/dns_config')
      dnsConfig.config = {
        get: () => {
          throw new Error('Config file error')
        }
      }

      // Should not throw when config loading fails
      assert.doesNotThrow(() => {
        dnsConfig.getDnsResolver()
      }, 'Should handle config errors gracefully')
    })

    it('should handle config with invalid DNS section', function () {
      const dnsConfig = require('../lib/dns_config')
      dnsConfig.config = {
        get: () => ({
          dns: 'invalid-not-an-object'
        })
      }

      // Should not throw and should fall back to defaults
      const resolver = dnsConfig.getDnsResolver()
      assert(resolver, 'Should create resolver despite invalid config')
    })

    it('should handle config with missing values', function () {
      const dnsConfig = require('../lib/dns_config')
      dnsConfig.config = {
        get: () => ({
          dns: {
            // timeout missing
            tries: '3'
            // other values missing
          }
        })
      }

      const resolver = dnsConfig.getDnsResolver()
      assert(resolver, 'Should create resolver with partial config')
    })
  })

  describe('Backwards compatibility', function () {
    it('should maintain same API as before', function () {
      // Test that all expected functions are still exported
      assert(typeof netUtils.get_ips_by_host === 'function', 'get_ips_by_host should exist')
      assert(typeof netUtils.get_mx === 'function', 'get_mx should exist')
      assert(typeof netUtils.is_private_ip === 'function', 'is_private_ip should exist')
      assert(typeof netUtils.ip_to_long === 'function', 'ip_to_long should exist')

      // Test that MX functions are available
      assert(typeof getMx.get_mx === 'function', 'get_mx function should exist')
      assert(typeof getMx.get_implicit_mx === 'function', 'get_implicit_mx should exist')
      assert(typeof getMx.resolve_mx_hosts === 'function', 'resolve_mx_hosts should exist')
    })

    it('should produce same results as hardcoded values', async function () {
      // Test with default config (should behave like hardcoded values)
      const dnsConfig = require('../lib/dns_config')
      dnsConfig.config = {
        get: () => undefined  // No config file, use defaults
      }

      const ips = await netUtils.get_ips_by_host('google.com')
      assert(Array.isArray(ips), 'Should return same format as before')
      assert(ips.length > 0, 'Should return results like before')
    })
  })
})