const assert = require('node:assert')
const os = require('node:os')
const path = require('node:path')

require('haraka-config').watch_files = false
const net_utils = require('../index')

function _check(done, ip, host, res) {
  assert.equal(net_utils.is_ip_in_str(ip, host), res)
  done()
}

describe('long_to_ip', function () {
  it('185999660', function (done) {
    assert.equal(net_utils.long_to_ip(185999660), '11.22.33.44')
    done()
  })
})

describe('static_rdns', function () {
  it('74.125.82.182', function (done) {
    _check(done, '74.125.82.182', 'mail-we0-f182.google.com', false)
  })
  it('74.125.82.53', function (done) {
    _check(done, '74.125.82.53', 'mail-ww0-f53.google.com', false)
  })
})

describe('dynamic_rdns', function () {
  it('109.168.232.131', function (done) {
    _check(done, '109.168.232.131', 'host-109-168-232-131.stv.ru', true)
  })
  it('62.198.236.129', function (done) {
    _check(done, '62.198.236.129', '0x3ec6ec81.inet.dsl.telianet.dk', true)
  })
  it('123.58.178.17', function (done) {
    _check(done, '123.58.178.17', 'm17-178.vip.126.com', true)
  })

  it('100.42.67.92', function (done) {
    _check(done, '100.42.67.92', '92-67-42-100-dedicated.multacom.com', true)
  })

  it('101.0.57.5', function (done) {
    _check(done, '101.0.57.5', 'static-bpipl-101.0.57-5.com', true)
  })
})

function _same_ipv4_network(done, addr, addrList, expected) {
  assert.equal(expected, net_utils.same_ipv4_network(addr, addrList))
  done()
}

describe('same_ipv4_network', function () {
  it('199.176.179.3 <-> [199.176.179.4]', function (done) {
    _same_ipv4_network(done, '199.176.179.3', ['199.176.179.4'], true)
  })

  it('199.176.179.3 <-> [199.177.179.4', function (done) {
    _same_ipv4_network(done, '199.176.179.3', ['199.177.179.4'], false)
  })

  it('199.176.179 <-> [199.176.179.4] (missing octet)', function (done) {
    _same_ipv4_network(done, '199.176.179', ['199.176.179.4'], false)
  })

  it('199.176.179.3.5 <-> [199.176.179.4] (extra octet)', function (done) {
    _same_ipv4_network(done, '199.176.179.3.5', ['199.176.179.4'], false)
  })
})

describe('is_ipv4_literal', function () {
  it('3 ways', function (done) {
    assert.equal(true, net_utils.is_ipv4_literal('[127.0.0.1]'))
    assert.equal(false, net_utils.is_ipv4_literal('127.0.0.1'))
    assert.equal(false, net_utils.is_ipv4_literal('test.host'))
    done()
  })
})

async function _is_local_host(done, host, expected) {
  const is_local_host = await net_utils.is_local_host(host)
  assert.strictEqual(expected, is_local_host)
  done()
}

function _is_private_ip(done, ip, expected) {
  assert.equal(expected, net_utils.is_private_ip(ip))
  done()
}

function _is_local_ip(done, ip, expected) {
  assert.equal(expected, net_utils.is_local_ip(ip))
  done()
}

describe('is_local_host', function () {
  it('127.0.0.1', function (done) {
    _is_local_host(done, '127.0.0.1', true)
  })

  it('0.0.0.0', function (done) {
    _is_local_host(done, '0.0.0.0', true)
  })

  it('::1', function (done) {
    _is_local_host(done, '::1', true)
  })

  it('self hostname', function (done) {
    if (/^win/.test(process.platform)) return done()
    const hostname = require('../index').get_primary_host_name()
    _is_local_host(done, hostname, true)
  })

  it('self ip', function (done) {
    require('../index')
      .get_public_ip()
      .then((ip) => {
        _is_local_host(done, ip, true)
      })
  })

  it('google.com', function (done) {
    _is_local_host(done, 'google.com', false)
  })

  it('8.8.8.8', function (done) {
    _is_local_host(done, '8.8.8.8', false)
  })

  it('invalid host string', async function () {
    const r = await net_utils.is_local_host('invalid host string')
    assert.ok(!r)
  })
})

describe('is_local_ip', function () {
  it('127.0.0.1', function (done) {
    _is_local_ip(done, '127.0.0.1', true)
  })

  it('::1', function (done) {
    _is_local_ip(done, '::1', true)
  })

  it('0:0:0:0:0:0:0:1', function (done) {
    _is_local_ip(done, '0:0:0:0:0:0:0:1', true)
  })

  it('0000:0000:0000:0000:0000:0000:0000:0001', function (done) {
    _is_local_ip(done, '0000:0000:0000:0000:0000:0000:0000:0001', true)
  })

  it('123.123.123.123 (!)', function (done) {
    _is_local_ip(done, '123.123.123.123', false)
  })

  it('dead::beef (!)', function (done) {
    _is_local_ip(done, 'dead::beef', false)
  })

  it('192.168.1 (missing octet)', function (done) {
    _is_local_ip(done, '192.168.1', false)
  })

  it('239.0.0.1 (multicast; not currently considered rfc1918)', function (done) {
    _is_local_ip(done, '239.0.0.1', false)
  })

  it('0.0.0.0', function (done) {
    _is_local_ip(done, '0.0.0.0', true)
  })

  it('::', function (done) {
    _is_local_ip(done, '::', true)
  })
})

describe('is_private_ip', function () {
  it('127.0.0.1', function (done) {
    _is_private_ip(done, '127.0.0.1', true)
  })

  it('10.255.31.23', function (done) {
    _is_private_ip(done, '10.255.31.23', true)
  })

  it('172.16.255.254', function (done) {
    _is_private_ip(done, '172.16.255.254', true)
  })

  it('192.168.123.123', function (done) {
    _is_private_ip(done, '192.168.123.123', true)
  })

  it('169.254.23.54 (APIPA)', function (done) {
    _is_private_ip(done, '169.254.23.54', true)
  })

  it('::1', function (done) {
    _is_private_ip(done, '::1', true)
  })

  it('0:0:0:0:0:0:0:1', function (done) {
    _is_private_ip(done, '0:0:0:0:0:0:0:1', true)
  })

  it('0000:0000:0000:0000:0000:0000:0000:0001', function (done) {
    _is_private_ip(done, '0000:0000:0000:0000:0000:0000:0000:0001', true)
  })

  it('123.123.123.123', function (done) {
    _is_private_ip(done, '123.123.123.123', false)
  })

  it('dead::beef', function (done) {
    _is_private_ip(done, 'dead::beef', false)
  })

  it('192.168.1 (missing octet)', function (done) {
    _is_private_ip(done, '192.168.1', false)
  })

  it('239.0.0.1 (multicast; not currently considered rfc1918)', function (done) {
    _is_private_ip(done, '239.0.0.1', false)
  })

  it('192.0.2.1 TEST-NET-1', function (done) {
    _is_private_ip(done, '192.0.2.1', true)
  })

  it('198.51.100.0 TEST-NET-2', function (done) {
    _is_private_ip(done, '198.51.100.0', true)
  })

  it('203.0.113.0 TEST-NET-3', function (done) {
    _is_private_ip(done, '203.0.113.0', true)
  })
})

describe('octets_in_string', function () {
  it('c-24-18-98-14.hsd1.wa.comcast.net', function (done) {
    const str = 'c-24-18-98-14.hsd1.wa.comcast.net'
    assert.equal(net_utils.octets_in_string(str, 98, 14), true)
    assert.equal(net_utils.octets_in_string(str, 24, 18), true)
    assert.equal(net_utils.octets_in_string(str, 2, 7), false)
    done()
  })

  it('149.213.210.203.in-addr.arpa', function (done) {
    const str = '149.213.210.203.in-addr.arpa'
    assert.equal(net_utils.octets_in_string(str, 149, 213), true)
    assert.equal(net_utils.octets_in_string(str, 210, 20), true)
    assert.equal(net_utils.octets_in_string(str, 2, 7), false)
    done()
  })
})

describe('is_ip_literal', function () {
  it('ipv4 is_ip_literal', function (done) {
    assert.equal(net_utils.is_ip_literal('[127.0.0.0]'), true)
    assert.equal(net_utils.is_ip_literal('[127.0.0.1]'), true)
    assert.equal(net_utils.is_ip_literal('[127.1.0.255]'), true)
    assert.equal(net_utils.is_ip_literal('127.0.0.0'), false)
    assert.equal(net_utils.is_ip_literal('127.0.0.1'), false)
    assert.equal(net_utils.is_ip_literal('127.1.0.255'), false)

    done()
  })

  it('ipv6 is_ip_literal', function (done) {
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

    done()
  })
})

describe('is_local_ipv4', function () {
  it('127/8', function (done) {
    assert.equal(net_utils.is_local_ipv4('127.0.0.0'), true)
    assert.equal(net_utils.is_local_ipv4('127.0.0.1'), true)
    assert.equal(net_utils.is_local_ipv4('127.1.0.255'), true)

    done()
  })

  it('0/8', function (done) {
    assert.equal(net_utils.is_local_ipv4('0.0.0.1'), false)
    assert.equal(net_utils.is_local_ipv4('0.255.0.1'), false)
    assert.equal(net_utils.is_local_ipv4('1.255.0.1'), false)
    assert.equal(net_utils.is_local_ipv4('10.255.0.1'), false)
    done()
  })
})

describe('is_private_ipv4', function () {
  it('10/8', function (done) {
    assert.equal(net_utils.is_private_ipv4('10.0.0.0'), true)
    assert.equal(net_utils.is_private_ipv4('10.255.0.0'), true)
    assert.equal(net_utils.is_private_ipv4('9.255.0.0'), false)
    assert.equal(net_utils.is_private_ipv4('11.255.0.0'), false)
    done()
  })

  it('192.168/16', function (done) {
    assert.equal(net_utils.is_private_ipv4('192.168.0.0'), true)
    assert.equal(net_utils.is_private_ipv4('192.169.0.0'), false)
    assert.equal(net_utils.is_private_ipv4('192.167.0.0'), false)
    done()
  })

  it('172.16-31', function (done) {
    assert.equal(net_utils.is_private_ipv4('172.16.0.0'), true)
    assert.equal(net_utils.is_private_ipv4('172.20.0.0'), true)
    assert.equal(net_utils.is_private_ipv4('172.31.0.0'), true)
    assert.equal(net_utils.is_private_ipv4('172.15.0.0'), false)
    assert.equal(net_utils.is_private_ipv4('172.32.0.0'), false)
    done()
  })
})

describe('is_local_ipv6', function () {
  it('::', function (done) {
    assert.equal(net_utils.is_local_ipv6('::'), true)
    done()
  })

  it('::1', function (done) {
    assert.equal(net_utils.is_local_ipv6('::1'), true)
    assert.equal(net_utils.is_local_ipv6('0:0:0:0:0:0:0:1'), true)
    assert.equal(
      net_utils.is_local_ipv6('0000:0000:0000:0000:0000:0000:0000:0001'),
      true,
    )
    done()
  })

  it('fe80::/10', function (done) {
    assert.equal(net_utils.is_local_ipv6('fe80::'), true)
    assert.equal(net_utils.is_local_ipv6('fe80:'), false)
    assert.equal(net_utils.is_local_ipv6('fe8:'), false)
    assert.equal(net_utils.is_local_ipv6(':fe80:'), false)
    done()
  })

  it('fc80::/7', function (done) {
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
    done()
  })
})

describe('get_ips_by_host', function () {
  const tests = {
    'servedby.tnpi.net': [
      '192.48.85.146',
      '192.48.85.147',
      '192.48.85.148',
      '192.48.85.149',
      '2607:f060:b008:feed::2',
    ],
    'localhost.haraka.tnpi.net': ['127.0.0.1', '::1'],
    // 'non-exist.haraka.tnpi.net': [],
  }

  for (const t in tests) {
    it(`get_ips_by_host, ${t}`, function (done) {
      this.timeout(7000)
      net_utils.get_ips_by_host(t, function (err, res) {
        if (err && err.length) {
          console.error(err)
          return done()
        }
        assert.deepEqual(err, [])
        assert.deepEqual(res.sort(), tests[t].sort())
        done()
      })
    })

    it(`get_ips_by_host, promise, ${t}`, async function () {
      try {
        const res = await net_utils.get_ips_by_host(t)
        assert.deepEqual(res.sort(), tests[t].sort())
      } catch (e) {
        console.error(e)
      }
    })
  }
})

function _check_list(done, list, ip, res) {
  assert.equal(net_utils.ip_in_list(list, ip), res) // keys of object
  assert.equal(net_utils.ip_in_list(Object.keys(list), ip), res) // array
  done()
}

describe('ip_in_list', function () {
  it('domain.com', function (done) {
    _check_list(done, { 'domain.com': undefined }, 'domain.com', true)
  })

  it('foo.com', function (done) {
    _check_list(done, {}, 'foo.com', false)
  })

  it('1.2.3.4', function (done) {
    _check_list(done, { '1.2.3.4': undefined }, '1.2.3.4', true)
  })

  it('1.2.3.4/32', function (done) {
    _check_list(done, { '1.2.3.4/32': undefined }, '1.2.3.4', true)
  })

  it('1.2.0.0/16 <-> 1.2.3.4', function (done) {
    _check_list(done, { '1.2.0.0/16': undefined }, '1.2.3.4', true)
  })

  it('1.2.0.0/16 <-> 5.6.7.8', function (done) {
    _check_list(done, { '1.2.0.0/16': undefined }, '5.6.7.8', false)
  })

  it('0000:0000:0000:0000:0000:0000:0000:0001', function (done) {
    _check_list(
      done,
      { '0000:0000:0000:0000:0000:0000:0000:0001': undefined },
      '0000:0000:0000:0000:0000:0000:0000:0001',
      true,
    )
  })

  it('0:0:0:0:0:0:0:1', function (done) {
    _check_list(
      done,
      { '0:0:0:0:0:0:0:1': undefined },
      '0000:0000:0000:0000:0000:0000:0000:0001',
      true,
    )
  })

  it('1.2 (bad config)', function (done) {
    _check_list(done, { 1.2: undefined }, '1.2.3.4', false)
  })

  it('1.2.3.4/ (mask ignored)', function (done) {
    _check_list(done, { '1.2.3.4/': undefined }, '1.2.3.4', true)
  })

  it('1.2.3.4/gr (mask ignored)', function (done) {
    _check_list(done, { '1.2.3.4/gr': undefined }, '1.2.3.4', true)
  })

  it('1.2.3.4/400 (mask read as 400 bits)', function (done) {
    _check_list(done, { '1.2.3.4/400': undefined }, '1.2.3.4', true)
  })
})

describe('get_primary_host_name', function () {
  beforeEach(function (done) {
    this.net_utils = require('../index')
    this.net_utils.config = this.net_utils.config.module_config(
      path.resolve('test'),
    )
    done()
  })

  it('with me config', function (done) {
    assert.equal(this.net_utils.get_primary_host_name(), 'test-hostname')
    done()
  })

  it('without me config', function (done) {
    this.net_utils.config = this.net_utils.config.module_config(
      path.resolve('doesnt-exist'),
    )
    assert.equal(this.net_utils.get_primary_host_name(), os.hostname())
    done()
  })
})

describe('on_local_interface', function () {
  beforeEach(function (done) {
    this.net_utils = require('../index')
    this.net_utils.config = this.net_utils.config.module_config(
      path.resolve('test'),
    )
    done()
  })

  it('localhost 127.0.0.1', function (done) {
    assert.equal(this.net_utils.on_local_interface('127.0.0.1'), true)
    done()
  })

  it('multicast 1.1.1.1', function (done) {
    assert.equal(this.net_utils.on_local_interface('1.1.1.1'), false)
    done()
  })

  it('ipv6 localhost ::1', function (done) {
    const r = this.net_utils.on_local_interface('::1')
    if (r) {
      assert.equal(r, true)
    }
    done()
  })
})
