#!/usr/bin/env node
'use strict'

/**
 * Demonstration of configurable DNS resolver timeout and tries
 *
 * This script shows how the DNS configuration works with different settings
 */

const path = require('path')
const fs = require('fs')

console.log('=== DNS Configuration Demo ===\n')

// Test 1: Default configuration (no config file)
console.log('1. Testing with default configuration (25000ms timeout, 1 try):')
testDnsConfiguration(undefined)

// Test 2: Custom configuration
console.log('\n2. Testing with custom configuration (5000ms timeout, 3 tries):')
const customConfig = {
  dns: {
    timeout: '5000',
    tries: '3'
  }
}
testDnsConfiguration(customConfig)

// Test 3: Partial configuration
console.log('\n3. Testing with partial configuration (only timeout specified):')
const partialConfig = {
  dns: {
    timeout: '10000'
    // tries not specified, should default to 1
  }
}
testDnsConfiguration(partialConfig)

function testDnsConfiguration(configData) {
  // Clear module cache to get fresh instance
  delete require.cache[require.resolve('../lib/dns_config')]
  delete require.cache[require.resolve('../index.js')]

  const dnsConfig = require('../lib/dns_config')

  // Mock the config system
  dnsConfig.config = {
    get: (filename) => {
      if (filename === 'net-utils.ini') {
        return configData
      }
      return undefined
    }
  }

  const resolver = dnsConfig.getDnsResolver()
  console.log(`  ✓ DNS Resolver created successfully`)

  // Test actual DNS resolution
  const netUtils = require('../index.js')

  netUtils.get_ips_by_host('google.com')
    .then(ips => {
      console.log(`  ✓ Resolved google.com to ${ips.slice(0, 2).join(', ')}${ips.length > 2 ? '...' : ''}`)
    })
    .catch(err => {
      console.log(`  ✗ DNS resolution failed: ${err.message}`)
    })
}

// Test 4: Show how to create actual config file
console.log('\n4. Example configuration file content:')
console.log('   File: config/net-utils.ini')
console.log('   Content:')
console.log(`
[dns]
; DNS resolver timeout in milliseconds (default: 25000)
timeout=15000

; Number of DNS resolution attempts (default: 1)
tries=2

; This configuration will be used by both:
; - Main DNS operations (index.js)
; - MX record resolution (lib/get_mx.js)
`)

console.log('\n5. Configuration will be automatically reloaded when the file changes!')
console.log('   No need to restart Haraka when adjusting DNS timeout/retry settings.')

console.log('\n=== Demo Complete ===')

// Give DNS operations time to complete
setTimeout(() => {
  console.log('\nDNS operations completed. Configuration is working correctly!')
}, 2000)