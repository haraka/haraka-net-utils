const assert = require('node:assert/strict')
const os = require('node:os')
const { describe, it, mock } = require('node:test')

// node --test runs each file in its own process, so this fixture fills the
// module's interface cache before any other lookup can.
mock.method(os, 'networkInterfaces', () => ({
  lo0: [{ address: '127.0.0.1' }, { address: '::1' }],
  en0: [
    { address: '192.168.1.10' },
    { address: '169.254.7.7' },
    { address: 'fe80::aaaa' },
    { address: 'fd00:abcd::5' },
  ],
}))

const net_utils = require('../index')

describe('is_local_ip with addresses bound on this host', () => {
  const cases = {
    '169.254.7.7': true,
    '169.254.8.8': false,
    'fe80::aaaa': true,
    'fe80::bbbb': false,
    'fd00:abcd::5': true,
    'fd00:abcd::6': false,
    '192.168.1.10': true,
    '192.168.1.11': false,
  }

  for (const [ip, expect] of Object.entries(cases)) {
    it(`${ip} is ${expect ? '' : 'not '}local`, () => {
      assert.equal(net_utils.is_local_ip(ip), expect)
    })
  }
})
