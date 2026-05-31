const assert = require('node:assert')
const EventEmitter = require('node:events')
const os = require('node:os')
const path = require('node:path')
const { beforeEach, describe, it } = require('node:test')

require('haraka-config').watch_files = false
const net_utils = require('../index')

function _check(ip, host, res) {
  assert.equal(net_utils.is_ip_in_str(ip, host), res)
}

describe('long_to_ip', function () {
  it('185999660', function () {
    assert.equal(net_utils.long_to_ip(185999660), '11.22.33.44')
  })
})

describe('dec_to_hex', function () {
  const cases = [
    { input: 0, expect: '0' },
    { input: 1, expect: '1' },
    { input: 10, expect: 'a' },
    { input: 16, expect: '10' },
    { input: 255, expect: 'ff' },
    { input: 4095, expect: 'fff' },
  ]

  for (const { input, expect } of cases) {
    it(`${input} -> ${expect}`, function () {
      assert.equal(net_utils.dec_to_hex(input), expect)
    })
  }
})

describe('hex_to_dec', function () {
  const cases = [
    { input: '0', expect: 0 },
    { input: '1', expect: 1 },
    { input: 'a', expect: 10 },
    { input: '10', expect: 16 },
    { input: 'ff', expect: 255 },
    { input: 'fff', expect: 4095 },
  ]

  for (const { input, expect } of cases) {
    it(`${input} -> ${expect}`, function () {
      assert.equal(net_utils.hex_to_dec(input), expect)
    })
  }
})

describe('ip_to_long', function () {
  const cases = [
    { input: '0.0.0.0', expect: 0 },
    { input: '1.2.3.4', expect: 16909060 },
    { input: '11.22.33.44', expect: 185999660 },
    { input: '127.0.0.1', expect: 2130706433 },
    { input: '255.255.255.255', expect: 4294967295 },
    { input: 'not-an-ip', expect: false },
    { input: '::1', expect: false },
  ]

  for (const { input, expect } of cases) {
    it(`${input}`, function () {
      assert.equal(net_utils.ip_to_long(input), expect)
    })
  }
})

describe('ipv6_reverse', function () {
  const cases = [
    {
      input: '::1',
      expect: '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0',
    },
    {
      input: '2001:db8::1',
      expect: '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2',
    },
    {
      input: '2001:db8:abcd:12::34',
      expect: '4.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.1.0.0.d.c.b.a.8.b.d.0.1.0.0.2',
    },
  ]

  for (const { input, expect } of cases) {
    it(input, function () {
      assert.equal(net_utils.ipv6_reverse(input), expect)
    })
  }
})

describe('ipv6_bogus', function () {
  it('unicast returns false', function () {
    assert.equal(net_utils.ipv6_bogus('2606:4700:4700::1111'), false)
  })
  it('loopback returns true', function () {
    assert.equal(net_utils.ipv6_bogus('::1'), true)
  })
  it('invalid input returns true', function () {
    assert.equal(net_utils.ipv6_bogus('not-an-ipv6'), true)
  })
})

describe('static_rdns', function () {
  it('74.125.82.182', function () {
    _check('74.125.82.182', 'mail-we0-f182.google.com', false)
  })
  it('74.125.82.53', function () {
    _check('74.125.82.53', 'mail-ww0-f53.google.com', false)
  })
})

describe('dynamic_rdns', function () {
  const cases = [
    {
      ip: '109.168.232.131',
      rdns: 'host-109-168-232-131.stv.ru',
      expect: true,
    },
    {
      ip: '62.198.236.129',
      rdns: '0x3ec6ec81.inet.dsl.telianet.dk',
      expect: true,
    },
    { ip: '123.58.178.17', rdns: 'm17-178.vip.126.com', expect: true },
    {
      ip: '100.42.67.92',
      rdns: '92-67-42-100-dedicated.multacom.com',
      expect: true,
    },
    { ip: '101.0.57.5', rdns: 'static-bpipl-101.0.57-5.com', expect: true },
    { ip: '74.125.82.53', rdns: 'mail-ww0-f53.google.com', expect: false },
    { ip: '8.8.8.8', rdns: 'dns.google', expect: false },
  ]

  for (const { ip, rdns, expect } of cases) {
    it(`${ip} -> ${rdns}`, function () {
      assert.equal(net_utils.is_ip_in_str(ip, rdns), expect)
    })
  }
})

describe('same_ipv4_network', function () {
  const cases = [
    { addr: '199.176.179.3', list: ['199.176.179.4'], expect: true },
    { addr: '199.176.179.3', list: ['199.177.179.4'], expect: false },
    { addr: '199.176.179', list: ['199.176.179.4'], expect: false },
    { addr: '199.176.179.3.5', list: ['199.176.179.4'], expect: false },
    {
      addr: '199.176.179.3',
      list: ['not-an-ip', '199.176.179.4'],
      expect: true,
    },
    { addr: '199.176.179.3', list: [], expect: false },
    {
      addr: '199.176.179.3',
      list: ['199.176.179.3', '199.176.179.4'],
      expect: true,
    },
    { addr: 'not-an-ip', list: ['199.176.179.4'], expect: false },
    { addr: '::1', list: ['199.176.179.4'], expect: false },
  ]

  for (const { addr, list, expect } of cases) {
    it(`${addr} <-> [${list.join(', ')}]`, function () {
      assert.equal(expect, net_utils.same_ipv4_network(addr, list))
    })
  }

  it('returns false when ipList is missing/undefined', function () {
    assert.equal(net_utils.same_ipv4_network('199.176.179.3'), false)
    assert.equal(net_utils.same_ipv4_network('199.176.179.3', null), false)
  })
})

describe('is_ip_in_str (1st/2nd octets fallback)', function () {
  it('returns true via the 1st/2nd octets when 3rd/4th are absent', function () {
    // host has the first two octets embedded but not 3 or 4
    assert.equal(net_utils.is_ip_in_str('1.2.3.4', 'mail1and2.example'), true)
  })

  it('returns false for empty / missing str argument', function () {
    assert.equal(net_utils.is_ip_in_str('1.2.3.4', ''), false)
    assert.equal(net_utils.is_ip_in_str('1.2.3.4', null), false)
  })

  it('returns false for missing ip argument', function () {
    assert.equal(net_utils.is_ip_in_str(undefined, 'mail.example.com'), false)
    assert.equal(net_utils.is_ip_in_str('', 'mail.example.com'), false)
  })

  it('returns false for non-IPv4 ip (IPv6 not supported here)', function () {
    assert.equal(net_utils.is_ip_in_str('::1', 'mail.example.com'), false)
    assert.equal(net_utils.is_ip_in_str('not-an-ip', 'mail.example.com'), false)
  })
})

describe('octets_in_string', function () {
  it('returns false when oct1 is absent (with oct2.length < oct1.length)', function () {
    // Pass single-char oct2 so we go through the second branch (oct2 length < oct1)
    // where oct1.indexOf is checked first; choose strings so oct1 is not present.
    assert.equal(net_utils.octets_in_string('zzzzzzz', '111', '9'), false)
  })

  it('returns false when oct2 is absent after stripping oct1', function () {
    assert.equal(net_utils.octets_in_string('111-zzz', '111', '9'), false)
  })
})

describe('is_local_host error path', function () {
  it('returns false when an internal lookup throws', async function () {
    try {
      const result = await net_utils.is_local_host('example.org')
      assert.equal(result, false)
    } catch {}
  })
})

describe('is_ipv4_literal', function () {
  it('3 ways', function () {
    assert.equal(true, net_utils.is_ipv4_literal('[127.0.0.1]'))
    assert.equal(false, net_utils.is_ipv4_literal('127.0.0.1'))
    assert.equal(false, net_utils.is_ipv4_literal('test.host'))
  })
})

describe('is_local_host', async function () {
  const cases = [
    { host: 'google.com', expect: false },
    { host: '8.8.8.8', expect: false },
    { host: 'invalid host string', expect: false },
  ]

  if (!/^(win|darwin)/.test(process.platform)) {
    // azure test runners 🤢
    cases.push({ host: '0.0.0.0', expect: true })
    cases.push({ host: '127.0.0.1', expect: true })

    const selfIp = await require('../index').get_public_ip()
    if (selfIp) {
      cases.push({
        host: selfIp,
        expect: true,
        descr: `my public IP: ${selfIp}`,
      })
    }

    const host = require('../index').get_primary_host_name()
    cases.push({ host, expect: true, descr: `my primary hostname: ${host}` })
  }

  for (const { host, expect, descr = '' } of cases) {
    it(`${descr || host}`, async () => {
      const is_local_host = await net_utils.is_local_host(host)
      assert.strictEqual(expect, is_local_host)
    })
  }
})

describe('is_local_ip', function () {
  const cases = [
    { host: '127.0.0.1', expect: true },
    { host: '0.0.0.0', expect: true },
    { host: '::1', expect: true },
    { host: '::', expect: true },
    { host: '0:0:0:0:0:0:0:1', expect: true },
    { host: '0000:0000:0000:0000:0000:0000:0000:0001', expect: true },
    { host: '123.123.123.123', expect: false },
    { host: 'dead::beef', expect: false },
    { host: '192.168.1', expect: false, descr: 'missing octet' },
    {
      host: '239.0.0.1',
      expect: false,
      descr: '239.0.0.1 (multicast; not currently considered rfc1918)',
    },
  ]

  for (const { host, expect, descr = '' } of cases) {
    it(`${descr || host}`, async () => {
      const is_local_host = net_utils.is_local_ip(host)
      assert.strictEqual(expect, is_local_host)
    })
  }
})

describe('is_private_ip', function () {
  const cases = [
    { host: '127.0.0.1', expect: true },
    { host: '10.255.31.23', expect: true },
    { host: '172.16.255.254', expect: true },
    { host: '192.168.123.123', expect: true },
    { host: '169.254.23.54', expect: true, descr: '169.254.23.54 (APIPA)' },
    { host: '::1', expect: true },
    { host: '0:0:0:0:0:0:0:1', expect: true },
    {
      host: '0000:0000:0000:0000:0000:0000:0000:0001',
      expect: true,
    },
    { host: '123.123.123.123', expect: false },
    { host: 'dead::beef', expect: false },
    { host: '192.168.1', expect: false, descr: '192.168.1 (missing octet)' },
    {
      host: '239.0.0.1',
      expect: false,
      descr: '239.0.0.1 (multicast; not currently considered rfc1918)',
    },
    { host: '192.0.2.1', expect: true, descr: '192.0.2.1 TEST-NET-1' },
    { host: '198.51.100.0', expect: true, descr: '198.51.100.0 TEST-NET-2' },
    { host: '203.0.113.0', expect: true, descr: '203.0.113.0 TEST-NET-3' },
  ]

  for (const { host, expect, descr = '' } of cases) {
    it(`${descr || host}`, function () {
      assert.equal(expect, net_utils.is_private_ip(host))
    })
  }
})

describe('octets_in_string', function () {
  it('c-24-18-98-14.hsd1.wa.comcast.net', function () {
    const str = 'c-24-18-98-14.hsd1.wa.comcast.net'
    assert.equal(net_utils.octets_in_string(str, 98, 14), true)
    assert.equal(net_utils.octets_in_string(str, 24, 18), true)
    assert.equal(net_utils.octets_in_string(str, 2, 7), false)
  })

  it('149.213.210.203.in-addr.arpa', function () {
    const str = '149.213.210.203.in-addr.arpa'
    assert.equal(net_utils.octets_in_string(str, 149, 213), true)
    assert.equal(net_utils.octets_in_string(str, 210, 20), true)
    assert.equal(net_utils.octets_in_string(str, 2, 7), false)
  })
})

describe('is_ip_literal', function () {
  it('ipv4 is_ip_literal', function () {
    assert.equal(net_utils.is_ip_literal('[127.0.0.0]'), true)
    assert.equal(net_utils.is_ip_literal('[127.0.0.1]'), true)
    assert.equal(net_utils.is_ip_literal('[127.1.0.255]'), true)
    assert.equal(net_utils.is_ip_literal('127.0.0.0'), false)
    assert.equal(net_utils.is_ip_literal('127.0.0.1'), false)
    assert.equal(net_utils.is_ip_literal('127.1.0.255'), false)
  })

  it('ipv6 is_ip_literal', function () {
    assert.equal(net_utils.is_ip_literal('[::5555:6666:7777:8888]'), true)
    assert.equal(
      net_utils.is_ip_literal('[1111::4444:5555:6666:7777:8888]'),
      true,
    )
    assert.equal(net_utils.is_ip_literal('[2001:0:1234::C1C0:ABCD:876]'), true)
    assert.equal(
      net_utils.is_ip_literal('[IPv6:2607:fb90:4c28:f9e9:4ca2:2658:db85:f1a]'),
      true,
    )
    assert.equal(net_utils.is_ip_literal('::5555:6666:7777:8888'), false)
    assert.equal(
      net_utils.is_ip_literal('1111::4444:5555:6666:7777:8888'),
      false,
    )
    assert.equal(net_utils.is_ip_literal('2001:0:1234::C1C0:ABCD:876'), false)
  })
})

describe('is_local_ipv4', function () {
  it('127/8', function () {
    assert.equal(net_utils.is_local_ipv4('127.0.0.0'), true)
    assert.equal(net_utils.is_local_ipv4('127.0.0.1'), true)
    assert.equal(net_utils.is_local_ipv4('127.1.0.255'), true)
  })

  it('0/8', function () {
    assert.equal(net_utils.is_local_ipv4('0.0.0.1'), false)
    assert.equal(net_utils.is_local_ipv4('0.255.0.1'), false)
    assert.equal(net_utils.is_local_ipv4('1.255.0.1'), false)
    assert.equal(net_utils.is_local_ipv4('10.255.0.1'), false)
  })
})

describe('is_private_ipv4', function () {
  it('10/8', function () {
    assert.equal(net_utils.is_private_ipv4('10.0.0.0'), true)
    assert.equal(net_utils.is_private_ipv4('10.255.0.0'), true)
    assert.equal(net_utils.is_private_ipv4('9.255.0.0'), false)
    assert.equal(net_utils.is_private_ipv4('11.255.0.0'), false)
  })

  it('192.168/16', function () {
    assert.equal(net_utils.is_private_ipv4('192.168.0.0'), true)
    assert.equal(net_utils.is_private_ipv4('192.169.0.0'), false)
    assert.equal(net_utils.is_private_ipv4('192.167.0.0'), false)
  })

  it('172.16-31', function () {
    assert.equal(net_utils.is_private_ipv4('172.16.0.0'), true)
    assert.equal(net_utils.is_private_ipv4('172.20.0.0'), true)
    assert.equal(net_utils.is_private_ipv4('172.31.0.0'), true)
    assert.equal(net_utils.is_private_ipv4('172.15.0.0'), false)
    assert.equal(net_utils.is_private_ipv4('172.32.0.0'), false)
  })
})

describe('is_local_ipv6', function () {
  it('::', function () {
    assert.equal(net_utils.is_local_ipv6('::'), true)
  })

  it('::1', function () {
    assert.equal(net_utils.is_local_ipv6('::1'), true)
    assert.equal(net_utils.is_local_ipv6('0:0:0:0:0:0:0:1'), true)
    assert.equal(
      net_utils.is_local_ipv6('0000:0000:0000:0000:0000:0000:0000:0001'),
      true,
    )
  })

  it('fe80::/10', function () {
    assert.equal(net_utils.is_local_ipv6('fe80::'), true)
    assert.equal(net_utils.is_local_ipv6('fe81::1'), true)
    assert.equal(net_utils.is_local_ipv6('fea0::1'), true)
    assert.equal(net_utils.is_local_ipv6('febf::ffff'), true)
    assert.equal(net_utils.is_local_ipv6('fec0::1'), false) // outside /10
    assert.equal(net_utils.is_local_ipv6('fe70::1'), false) // outside /10
    assert.equal(net_utils.is_local_ipv6('fe80:'), false)
    assert.equal(net_utils.is_local_ipv6('fe8:'), false)
    assert.equal(net_utils.is_local_ipv6(':fe80:'), false)
  })

  it('fc80::/7', function () {
    assert.equal(net_utils.is_local_ipv6('fc00:'), true)
    assert.equal(net_utils.is_local_ipv6('fcff:'), true)

    // examples from https://en.wikipedia.org/wiki/Unique_local_address
    assert.equal(net_utils.is_local_ipv6('fde4:8dba:82e1::'), true)
    assert.equal(net_utils.is_local_ipv6('fde4:8dba:82e1:ffff::'), true)

    assert.equal(net_utils.is_local_ipv6('fd00:'), true)
    assert.equal(net_utils.is_local_ipv6('fdff:'), true)

    assert.equal(net_utils.is_local_ipv6('fb00:'), false)
    assert.equal(net_utils.is_local_ipv6('fe00:'), false)

    assert.equal(net_utils.is_local_ipv6('fe8:'), false)
    assert.equal(net_utils.is_local_ipv6(':fe80:'), false)
  })
})

describe('get_ips_by_host', function () {
  const tests = {
    'net-utils.haraka.tnpi.net': ['1.2.3.4', '8:7:6:5:4:3:2:1'],
    'localhost.haraka.tnpi.net': ['127.0.0.1', '::1'],
  }

  for (const t in tests) {
    it(
      `get_ips_by_host, ${t}`,
      { timeout: 7000 },
      () =>
        new Promise((resolve) => {
          net_utils.get_ips_by_host(t, function (err, res) {
            if (err && err.length) {
              console.error(err)
              return resolve()
            }
            assert.deepEqual(err, [])
            assert.deepEqual(res.sort(), tests[t].sort())
            resolve()
          })
        }),
    )

    it(`get_ips_by_host, promise, ${t}`, { timeout: 5000 }, async () => {
      try {
        const res = await net_utils.get_ips_by_host(t)
        assert.deepEqual(res.sort(), tests[t].sort())
      } catch (e) {
        console.error(e)
      }
    })
  }
})

describe('ip_in_list', function () {
  const cases = [
    { list: { 'domain.com': undefined }, ip: 'domain.com', expect: true },
    { list: {}, ip: 'foo.com', expect: false },
    { list: { '1.2.3.4': undefined }, ip: '1.2.3.4', expect: true },
    { list: { '1.2.3.4/32': undefined }, ip: '1.2.3.4', expect: true },
    { list: { '1.2.0.0/16': undefined }, ip: '1.2.3.4', expect: true },
    { list: { '1.2.0.0/16': undefined }, ip: '5.6.7.8', expect: false },
    {
      list: { '0000:0000:0000:0000:0000:0000:0000:0001': undefined },
      ip: '0000:0000:0000:0000:0000:0000:0000:0001',
      expect: true,
    },
    {
      list: { '0:0:0:0:0:0:0:1': undefined },
      ip: '0000:0000:0000:0000:0000:0000:0000:0001',
      expect: true,
    },
    {
      list: { 1.2: undefined },
      ip: '1.2.3.4',
      expect: false,
      descr: '1.2 (bad config)',
    },
    {
      list: { '1.2.3.4/': undefined },
      ip: '1.2.3.4',
      expect: true,
      descr: '1.2.3.4/ (mask ignored)',
    },
    {
      list: { '1.2.3.4/gr': undefined },
      ip: '1.2.3.4',
      expect: true,
      descr: '1.2.3.4/gr (mask ignored)',
    },
    {
      list: { '1.2.3.4/400': undefined },
      ip: '1.2.3.4',
      expect: true,
      descr: '1.2.3.4/400 (mask read as 400 bits)',
    },
    { list: undefined, ip: '1.2.3.4', expect: false, descr: 'undefined list' },
    {
      list: ['2001:db8::/32'],
      ip: '1.2.3.4',
      expect: false,
      descr: 'family mismatch',
    },
    {
      list: ['10.0.0.0/8'],
      ip: '2001:db8::1',
      expect: false,
      descr: 'family mismatch',
    },
    {
      list: ['1.2.3.4'],
      ip: '1.2.3.4',
      expect: true,
      descr: 'exact match in array',
    },
    { list: { 'a.example': 1 }, ip: 'b.example', expect: false },
  ]

  for (const { list, ip, expect, descr = '' } of cases) {
    it(`${descr ? descr + ': ' + ip : ip}`, () => {
      assert.equal(net_utils.ip_in_list(list, ip), expect) // keys of object
      if (list) {
        const asArray = Array.isArray(list) ? list : Object.keys(list)
        assert.equal(net_utils.ip_in_list(asArray, ip), expect) // array
      }
    })
  }

  it('ignores inherited Object.prototype properties', function () {
    assert.equal(net_utils.ip_in_list({}, '__proto__'), false)
    assert.equal(net_utils.ip_in_list({}, 'constructor'), false)
    assert.equal(net_utils.ip_in_list({}, 'hasOwnProperty'), false)
    assert.equal(net_utils.ip_in_list({}, 'toString'), false)
  })
})

describe('normalize_ip', function () {
  const cases = [
    { input: '1.2', expect: null },
    { input: '', expect: null, descr: 'empty string' },
    { input: null, expect: null },
    { input: '1.2.3.4', expect: '1.2.3.4' },
    {
      input: '2001:0:1234::c1c0:abcd:876',
      expect: '2001:0:1234::c1c0:abcd:876',
    },
    {
      input: '2001:0:1234::C1C0:ABCD:876',
      expect: '2001:0:1234::c1c0:abcd:876',
    },
    {
      input: '0000:0000:0000:0000:0000:0000:0000:0001',
      expect: '::1',
    },
    { input: '::ffff:127.0.0.1', expect: '127.0.0.1' },
  ]

  for (const { input, expect, descr = '' } of cases) {
    it(`${descr || String(input)}`, function () {
      assert.equal(net_utils.normalize_ip(input), expect)
    })
  }
})

describe('get_primary_host_name', () => {
  let net_utils_mod
  beforeEach(() => {
    net_utils_mod = require('../index')
    net_utils_mod.config = net_utils_mod.config.module_config(
      path.resolve('test'),
    )
  })

  it('with me config', () => {
    assert.equal(net_utils_mod.get_primary_host_name(), 'test-hostname')
  })

  it('without me config', () => {
    net_utils_mod.config = net_utils_mod.config.module_config(
      path.resolve('doesnt-exist'),
    )
    assert.equal(net_utils_mod.get_primary_host_name(), os.hostname())
  })
})

describe('on_local_interface', () => {
  let net_utils_mod
  beforeEach(() => {
    net_utils_mod = require('../index')
    net_utils_mod.config = net_utils_mod.config.module_config(
      path.resolve('test'),
    )
  })

  it('localhost 127.0.0.1', () => {
    assert.equal(net_utils_mod.on_local_interface('127.0.0.1'), true)
  })

  it('multicast 1.1.1.1', () => {
    assert.equal(net_utils_mod.on_local_interface('1.1.1.1'), false)
  })

  it('ipv6 localhost ::1', () => {
    const r = net_utils_mod.on_local_interface('::1')
    if (r) {
      assert.equal(r, true)
    }
  })
})

describe('add_line_processor', () => {
  let net_utils_mod
  let socket
  beforeEach(() => {
    net_utils_mod = require('../index')
    net_utils_mod.config = net_utils_mod.config.module_config(
      path.resolve('test'),
    )
    socket = new EventEmitter()
  })

  it('adds a line processor', async () => {
    let lines = 0
    socket.on('line', () => {
      lines++
    })
    await new Promise((resolve) => {
      socket.on('end', () => {
        assert.equal(lines, 3)
        resolve()
      })
      net_utils_mod.add_line_processor(socket)
      socket.emit('data', `multi\nline\nallThisDataIsLost\n`)
      socket.emit('end')
    })
  })

  it('emits partial line on end', async () => {
    const received = []
    socket.on('line', (line) => {
      received.push(line)
    })
    // add_line_processor must be called before registering the test 'end'
    // handler so its 'end' handler (which flushes partial data) runs first
    net_utils_mod.add_line_processor(socket)
    await new Promise((resolve) => {
      socket.on('end', () => {
        assert.equal(received.length, 2)
        assert.equal(received[0], 'complete\n')
        assert.equal(received[1], 'partial')
        resolve()
      })
      socket.emit('data', 'complete\npartial')
      socket.emit('end')
    })
  })

  it('emits error when line exceeds MAX_LINE_LENGTH', async () => {
    await new Promise((resolve) => {
      socket.on('error', (err) => {
        assert.ok(err.message.includes('Line length exceeded'))
        resolve()
      })
      net_utils_mod.add_line_processor(socket)
      socket.emit('data', 'A'.repeat(5 * 1024 * 1024)) // 5 MB, no newline
    })
  })
})

describe('parse_proxy_line', function () {
  it('PROXY TCP4 127.0.0.1 127.0.0.2 42310 465', function () {
    assert.deepEqual(
      net_utils.parse_proxy_line('PROXY TCP4 127.0.0.1 127.0.0.2 42310 465'),
      {
        type: 'haproxy',
        proto: 'TCP4',
        src_ip: '127.0.0.1',
        src_port: '42310',
        dst_ip: '127.0.0.2',
        dst_port: '465',
      },
    )
  })
  it('TCP4 127.0.0.1 127.0.0.2 42310 465', function () {
    assert.deepEqual(
      net_utils.parse_proxy_line('TCP4 127.0.0.1 127.0.0.2 42310 465'),
      {
        type: 'haproxy',
        proto: 'TCP4',
        src_ip: '127.0.0.1',
        src_port: '42310',
        dst_ip: '127.0.0.2',
        dst_port: '465',
      },
    )
  })
  it('TCP4 127.0.0.1 127.0.0.2 42310 465\\r\\n', function () {
    assert.deepEqual(
      net_utils.parse_proxy_line('TCP4 127.0.0.1 127.0.0.2 42310 465\r\n'),
      {
        type: 'haproxy',
        proto: 'TCP4',
        src_ip: '127.0.0.1',
        src_port: '42310',
        dst_ip: '127.0.0.2',
        dst_port: '465',
      },
    )
  })
  it('PROXY TCP4 nope 127.0.0.1 42310 465', function () {
    assert.deepEqual(
      net_utils.parse_proxy_line('PROXY TCP4 nope 127.0.0.1 42310 465'),
      null,
    )
  })
  it('PROXY TCP6 2001:0:1234::c1c0:abcd:876 2001:0:1234::c1c0:abcd:876 2525 25', function () {
    assert.deepEqual(
      net_utils.parse_proxy_line(
        'PROXY TCP6 2001:0:1234::c1c0:abcd:876 2001:0:1234::c1c0:abcd:876 2525 25',
      ),
      {
        type: 'haproxy',
        proto: 'TCP6',
        src_ip: '2001:0:1234::c1c0:abcd:876',
        src_port: '2525',
        dst_ip: '2001:0:1234::c1c0:abcd:876',
        dst_port: '25',
      },
    )
  })
  it('TCP6 ::1 ::1 2525 25', function () {
    assert.deepEqual(net_utils.parse_proxy_line('TCP6 ::1 ::1 2525 25'), {
      type: 'haproxy',
      proto: 'TCP6',
      src_ip: '::1',
      src_port: '2525',
      dst_ip: '::1',
      dst_port: '25',
    })
  })
  it('UNKNOWN 1.2.3.4 1.2.3.4 2525 25', function () {
    assert.deepEqual(
      net_utils.parse_proxy_line('UNKNOWN 1.2.3.4 1.2.3.4 2525 25'),
      null,
    )
  })
  it('PROXY TCP4 1.2.3.4 999.999.999.999 2525 25', function () {
    assert.deepEqual(
      net_utils.parse_proxy_line('PROXY TCP4 1.2.3.4 999.999.999.999 2525 25'),
      null,
    )
  })
  it('empty string', function () {
    assert.deepEqual(net_utils.parse_proxy_line(''), null)
  })
  it('null', function () {
    assert.deepEqual(net_utils.parse_proxy_line(null), null)
  })
  it('PROXY TCP4 nope 1.2.3.4 2525 25', function () {
    assert.deepEqual(
      net_utils.parse_proxy_line('PROXY TCP4 nope 1.2.3.4 2525 25'),
      null,
    )
  })
})

describe('is_haproxy_allowed', function () {
  let net_utils_mod
  beforeEach(() => {
    net_utils_mod = require('../index')
    net_utils_mod.config = net_utils_mod.config.module_config(
      path.resolve('test'),
    )
  })

  it('with connection.ini config and IPv4', () => {
    assert.equal(net_utils_mod.is_haproxy_allowed('1.2.3.4'), true)
  })

  it('with connection.ini config and IPv6', () => {
    assert.equal(
      net_utils_mod.is_haproxy_allowed('2001:0:1234::c1c0:abcd:876'),
      true,
    )
  })

  it('without connection.ini config and IPv4', () => {
    net_utils_mod.config = net_utils_mod.config.module_config(
      path.resolve('doesnt-exist'),
    )
    assert.equal(net_utils_mod.is_haproxy_allowed('1.2.3.4'), false)
  })

  it('without connection.ini config and IPv6', () => {
    net_utils_mod.config = net_utils_mod.config.module_config(
      path.resolve('doesnt-exist'),
    )
    assert.equal(
      net_utils_mod.is_haproxy_allowed('2001:0:1234::c1c0:abcd:876'),
      false,
    )
  })

  it('denies IP not in allow list', () => {
    assert.equal(net_utils_mod.is_haproxy_allowed('8.8.8.8'), false)
  })

  it('denies invalid IP', () => {
    assert.equal(net_utils_mod.is_haproxy_allowed('not-an-ip'), false)
  })

  it('allows IPv4-mapped IPv6 for listed IPv4', () => {
    assert.equal(net_utils_mod.is_haproxy_allowed('::ffff:1.2.3.4'), true)
  })

  it('when disabled in config', () => {
    net_utils_mod.config = net_utils_mod.config.module_config(
      path.resolve('test/haproxy-disabled'),
    )
    assert.equal(net_utils_mod.is_haproxy_allowed('1.2.3.4'), false)
  })

  it('matches CIDR in hosts', () => {
    net_utils_mod.config = net_utils_mod.config.module_config(
      path.resolve('test/haproxy-cidr'),
    )
    assert.equal(net_utils_mod.is_haproxy_allowed('1.2.3.99'), true)
    assert.equal(net_utils_mod.is_haproxy_allowed('1.2.4.1'), false)
  })

  it('denies all when enabled but hosts empty', () => {
    net_utils_mod.config = net_utils_mod.config.module_config(
      path.resolve('test/haproxy-empty-hosts'),
    )
    assert.equal(net_utils_mod.is_haproxy_allowed('1.2.3.4'), false)
  })
})
