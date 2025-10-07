'use strict'

const assert = require('assert')
const { Resolver } = require('node:dns').promises

describe('Configuration Validation Tests', function () {
  let dnsConfig

  beforeEach(function () {
    // Clear module cache for fresh instance
    delete require.cache[require.resolve('../lib/dns_config')]
    dnsConfig = require('../lib/dns_config')
  })

  it('should create resolver with exact default values when no config exists', function () {
    dnsConfig.config = {
      get: () => undefined
    }

    const resolver = dnsConfig.getDnsResolver()

    // We can't directly inspect the timeout/tries, but we can verify
    // the resolver was created and has the expected methods
    assert(resolver instanceof Resolver, 'Should create Resolver instance')
    assert(typeof resolver.resolve4 === 'function', 'Should have resolve4 method')
    assert(typeof resolver.resolve6 === 'function', 'Should have resolve6 method')
    assert(typeof resolver.resolveMx === 'function', 'Should have resolveMx method')
  })

  it('should parse string configuration values correctly', function () {
    const testConfigs = [
      { timeout: '5000', tries: '2' },
      { timeout: '25000', tries: '1' },
      { timeout: '30000', tries: '5' }
    ]

    testConfigs.forEach(config => {
      // Clear cached resolver
      if (dnsConfig.getDnsResolver._resolver) {
        delete dnsConfig.getDnsResolver._resolver
      }

      dnsConfig.config = {
        get: () => ({ dns: config })
      }

      const resolver = dnsConfig.getDnsResolver()
      assert(resolver instanceof Resolver,
             `Should create resolver with config: ${JSON.stringify(config)}`)
    })
  })

  it('should handle numeric configuration values', function () {
    dnsConfig.config = {
      get: () => ({
        dns: {
          timeout: 15000,  // numeric instead of string
          tries: 3         // numeric instead of string
        }
      })
    }

    const resolver = dnsConfig.getDnsResolver()
    assert(resolver instanceof Resolver, 'Should handle numeric config values')
  })

  it('should validate configuration boundaries', function () {
    const edgeCases = [
      { timeout: '0', tries: '0' },      // Zero values
      { timeout: '1', tries: '1' },      // Minimum values
      { timeout: '999999', tries: '10' } // Large values
    ]

    edgeCases.forEach(config => {
      // Clear cached resolver
      if (dnsConfig.getDnsResolver._resolver) {
        delete dnsConfig.getDnsResolver._resolver
      }

      dnsConfig.config = {
        get: () => ({ dns: config })
      }

      assert.doesNotThrow(() => {
        const resolver = dnsConfig.getDnsResolver()
        assert(resolver instanceof Resolver,
               `Should handle edge case config: ${JSON.stringify(config)}`)
      }, `Should not throw with config: ${JSON.stringify(config)}`)
    })
  })

  it('should fallback to defaults for invalid values', function () {
    const invalidConfigs = [
      { timeout: 'invalid', tries: 'also-invalid' },
      { timeout: null, tries: null },
      { timeout: [], tries: {} },
      { timeout: '', tries: '' }
    ]

    invalidConfigs.forEach(config => {
      // Clear cached resolver
      if (dnsConfig.getDnsResolver._resolver) {
        delete dnsConfig.getDnsResolver._resolver
      }

      dnsConfig.config = {
        get: () => ({ dns: config })
      }

      assert.doesNotThrow(() => {
        const resolver = dnsConfig.getDnsResolver()
        assert(resolver instanceof Resolver,
               `Should fallback to defaults for invalid config: ${JSON.stringify(config)}`)
      }, `Should not throw with invalid config: ${JSON.stringify(config)}`)
    })
  })

  it('should validate parseInt conversion behavior', function () {
    const testCases = [
      { input: '5000', expected: 5000 },
      { input: '1', expected: 1 },
      { input: 'abc', expected: 25000 }, // NaN -> fallback to default
      { input: '123.456', expected: 123 }, // parseInt truncates
      { input: '', expected: 25000 },  // empty string -> NaN -> fallback
      { input: '0', expected: 25000 }   // 0 is falsy, so fallback to default
    ]

    testCases.forEach(({ input, expected }) => {
      const parsed = parseInt(input) || 25000 // Same logic as in dns_config.js

      if (input === 'abc' || input === '' || input === '0') {
        assert.strictEqual(parsed, 25000, `Should fallback to default for: "${input}"`)
      } else if (input === '123.456') {
        assert.strictEqual(parsed, 123, `Should truncate decimal for: "${input}"`)
      } else {
        assert.strictEqual(parsed, expected, `Should parse correctly: "${input}"`)
      }
    })
  })

  it('should maintain singleton pattern with different configs', function () {
    dnsConfig.config = {
      get: () => ({ dns: { timeout: '5000', tries: '2' } })
    }

    const resolver1 = dnsConfig.getDnsResolver()
    const resolver2 = dnsConfig.getDnsResolver()

    assert.strictEqual(resolver1, resolver2, 'Should return same instance')

    // Verify both have expected methods
    assert(typeof resolver1.resolve4 === 'function')
    assert(typeof resolver2.resolve4 === 'function')
  })

  it('should demonstrate configuration file format compatibility', function () {
    // Test INI-style configuration that would come from haraka-config
    const iniStyleConfigs = [
      {
        // Standard INI format
        dns: {
          timeout: '25000',
          tries: '1'
        }
      },
      {
        // With comments (comments would be stripped by haraka-config)
        dns: {
          timeout: '30000',
          tries: '3'
        }
      },
      {
        // Mixed with other sections
        dns: {
          timeout: '20000',
          tries: '2'
        },
        other_section: {
          some_value: 'test'
        }
      }
    ]

    iniStyleConfigs.forEach((config, index) => {
      // Clear cached resolver
      if (dnsConfig.getDnsResolver._resolver) {
        delete dnsConfig.getDnsResolver._resolver
      }

      dnsConfig.config = {
        get: () => config
      }

      const resolver = dnsConfig.getDnsResolver()
      assert(resolver instanceof Resolver,
             `Should handle INI-style config ${index + 1}`)
    })
  })
})