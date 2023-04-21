
const assert = require('assert')
const net    = require('net')
const os     = require('os')
const path   = require('path')

require('haraka-config').watch_files = false;
const net_utils = require('../index');

function _check (done, ip, host, res) {
  assert.equal(net_utils.is_ip_in_str(ip, host), res);
  done();
}

describe('long_to_ip', function () {
  it('185999660', function (done) {
    assert.equal(net_utils.long_to_ip(185999660), '11.22.33.44');
    done();
  })
})

describe('static_rdns', function () {
  it('74.125.82.182', function (done) {
    _check(done, '74.125.82.182', 'mail-we0-f182.google.com', false);
  })
  it('74.125.82.53', function (done) {
    _check(done, '74.125.82.53', 'mail-ww0-f53.google.com', false);
  })
})

describe('dynamic_rdns', function () {

  it('109.168.232.131', function (done) {
    _check(done, '109.168.232.131', 'host-109-168-232-131.stv.ru', true);
  })
  it('62.198.236.129', function (done) {
    _check(done, '62.198.236.129', '0x3ec6ec81.inet.dsl.telianet.dk', true);
  })
  it('123.58.178.17', function (done) {
    _check(done, '123.58.178.17', 'm17-178.vip.126.com', true);
  })

  it('100.42.67.92', function (done) {
    _check(done, '100.42.67.92', '92-67-42-100-dedicated.multacom.com',
      true);
  })

  it('101.0.57.5', function (done) {
    _check(done, '101.0.57.5', 'static-bpipl-101.0.57-5.com', true);
  })
})

function _same_ipv4_network (done, addr, addrList, expected) {
  assert.equal(expected, net_utils.same_ipv4_network(addr, addrList));
  done();
}

describe('same_ipv4_network', function () {
  it('199.176.179.3 <-> [199.176.179.4]', function (done) {
    _same_ipv4_network(done, '199.176.179.3', ['199.176.179.4'], true);
  })

  it('199.176.179.3 <-> [199.177.179.4', function (done) {
    _same_ipv4_network(done, '199.176.179.3', ['199.177.179.4'], false);
  })

  it('199.176.179 <-> [199.176.179.4] (missing octet)', function (done) {
    _same_ipv4_network(done, '199.176.179', ['199.176.179.4'], false);
  })

  it('199.176.179.3.5 <-> [199.176.179.4] (extra octet)', function (done) {
    _same_ipv4_network(done, '199.176.179.3.5', ['199.176.179.4'], false);
  })
})

describe('is_ipv4_literal', function () {
  it('3 ways', function (done) {
    assert.equal(true,  net_utils.is_ipv4_literal('[127.0.0.1]'));
    assert.equal(false, net_utils.is_ipv4_literal('127.0.0.1'));
    assert.equal(false, net_utils.is_ipv4_literal('test.host'));
    done();
  })
})

async function _is_local_host (done, host, expected) {
  const is_local_host = await net_utils.is_local_host(host);
  assert.strictEqual(expected, is_local_host);
  done();
}

function _is_private_ip (done, ip, expected) {
  assert.equal(expected, net_utils.is_private_ip(ip));
  done();
}

function _is_local_ip (done, ip, expected) {
  assert.equal(expected, net_utils.is_local_ip(ip));
  done();
}

describe('is_local_host', function () {
  it('127.0.0.1', function (done) {
    _is_local_host(done, '127.0.0.1', true);
  })

  it('0.0.0.0', function (done) {
    _is_local_host(done, '0.0.0.0', true);
  })

  it('::1', function (done) {
    _is_local_host(done, '::1', true);
  })

  it('self hostname', function (done) {
    if (/^win/.test(process.platform)) return done()
    const hostname = require('../index').get_primary_host_name();
    _is_local_host(done, hostname, true);
  })

  it('self ip', function (done) {
    require('../index').get_public_ip().then(ip => {
      _is_local_host(done, ip, true);
    });
  })

  it('google.com', function (done) {
    _is_local_host(done, 'google.com', false);
  })

  it('8.8.8.8', function (done) {
    _is_local_host(done, '8.8.8.8', false);
  })

  it('invalid host string', async function () {
    const r = await net_utils.is_local_host('invalid host string')
    assert.ok(!r);
  })
})

describe('is_local_ip', function () {
  it('127.0.0.1', function (done) {
    _is_local_ip(done, '127.0.0.1', true);
  })

  it('::1', function (done) {
    _is_local_ip(done, '::1', true);
  })

  it('0:0:0:0:0:0:0:1', function (done) {
    _is_local_ip(done, '0:0:0:0:0:0:0:1', true);
  })

  it('0000:0000:0000:0000:0000:0000:0000:0001', function (done) {
    _is_local_ip(done, '0000:0000:0000:0000:0000:0000:0000:0001', true);
  })

  it('123.123.123.123 (!)', function (done) {
    _is_local_ip(done, '123.123.123.123', false);
  })

  it('dead::beef (!)', function (done) {
    _is_local_ip(done, 'dead::beef', false);
  })

  it('192.168.1 (missing octet)', function (done) {
    _is_local_ip(done, '192.168.1', false);
  })

  it('239.0.0.1 (multicast; not currently considered rfc1918)', function (done) {
    _is_local_ip(done, '239.0.0.1', false);
  })

  it('0.0.0.0', function (done) {
    _is_local_ip(done, '0.0.0.0', true);
  })

  it('::', function (done) {
    _is_local_ip(done, '::', true);
  })
})

describe('is_private_ip', function () {
  it('127.0.0.1', function (done) {
    _is_private_ip(done, '127.0.0.1', true);
  })

  it('10.255.31.23', function (done) {
    _is_private_ip(done, '10.255.31.23', true);
  })

  it('172.16.255.254', function (done) {
    _is_private_ip(done, '172.16.255.254', true);
  })

  it('192.168.123.123', function (done) {
    _is_private_ip(done, '192.168.123.123', true);
  })

  it('169.254.23.54 (APIPA)', function (done) {
    _is_private_ip(done, '169.254.23.54', true);
  })

  it('::1', function (done) {
    _is_private_ip(done, '::1', true);
  })

  it('0:0:0:0:0:0:0:1', function (done) {
    _is_private_ip(done, '0:0:0:0:0:0:0:1', true);
  })

  it('0000:0000:0000:0000:0000:0000:0000:0001', function (done) {
    _is_private_ip(done, '0000:0000:0000:0000:0000:0000:0000:0001', true);
  })

  it('123.123.123.123', function (done) {
    _is_private_ip(done, '123.123.123.123', false);
  })

  it('dead::beef', function (done) {
    _is_private_ip(done, 'dead::beef', false);
  })

  it('192.168.1 (missing octet)', function (done) {
    _is_private_ip(done, '192.168.1', false);
  })

  it('239.0.0.1 (multicast; not currently considered rfc1918)', function (done) {
    _is_private_ip(done, '239.0.0.1', false);
  })

  it('192.0.2.1 TEST-NET-1', function (done) {
    _is_private_ip(done, '192.0.2.1', true);
  })

  it('198.51.100.0 TEST-NET-2', function (done) {
    _is_private_ip(done, '198.51.100.0', true);
  })

  it('203.0.113.0 TEST-NET-3', function (done) {
    _is_private_ip(done, '203.0.113.0', true);
  })
})

describe('get_public_ip', function () {

  beforeEach(function (done) {
    this.net_utils = require('../index');
    this.net_utils.config = this.net_utils.config.module_config(path.resolve('test'));
    done();
  })

  function has_stun () {
    try {
      require('stun');
    }
    catch (e) {
      return false;
    }
    return true;
  }

  it('cached', function (done) {
    this.net_utils.public_ip='1.1.1.1';
    const cb = function (err, ip) {
      assert.equal(null, err);
      assert.equal('1.1.1.1', ip);
      done();
    };
    this.net_utils.get_public_ip(cb);
  })

  it('normal', function (done) {
    this.net_utils.public_ip=undefined;
    const cb = function (err, ip) {
      // console.log(`ip: ${ip}`);
      // console.log(`err: ${err}`);
      if (has_stun()) {
        if (err) {
          console.log(err);
        }
        else {
          console.log(`stun success: ${ip}`);
          assert.equal(null, err);
          assert.ok(ip, ip);
        }
      }
      else {
        console.log("stun skipped");
      }
      done();
    };
    this.net_utils.get_public_ip(cb);
  })
})

describe('get_public_ip_async', function () {

  beforeEach(() => {
    this.net_utils = require('../index');
    this.net_utils.config = this.net_utils.config.module_config(path.resolve('test'));
  })

  function has_stun () {
    try {
      require('stun');
    }
    catch (e) {
      return false;
    }
    return true;
  }

  it('cached', async () => {
    this.net_utils.public_ip='1.1.1.1';
    const ip = await this.net_utils.get_public_ip()
    assert.equal('1.1.1.1', ip);
  })

  it('normal', async () => {
    this.net_utils.public_ip=undefined;

    if (!has_stun()) {
      console.log("stun skipped");
      return
    }

    try {
      const ip = await this.net_utils.get_public_ip()
      console.log(`stun success: ${ip}`);
      assert.ok(ip, ip);
    }
    catch (e) {
      console.error(e);
    }
  })
})

describe('octets_in_string', function () {
  it('c-24-18-98-14.hsd1.wa.comcast.net', function (done) {
    const str = 'c-24-18-98-14.hsd1.wa.comcast.net';
    assert.equal(net_utils.octets_in_string(str, 98, 14), true );
    assert.equal(net_utils.octets_in_string(str, 24, 18), true );
    assert.equal(net_utils.octets_in_string(str, 2, 7), false );
    done();
  })

  it('149.213.210.203.in-addr.arpa', function (done) {
    const str = '149.213.210.203.in-addr.arpa';
    assert.equal(net_utils.octets_in_string(str, 149, 213), true );
    assert.equal(net_utils.octets_in_string(str, 210, 20), true );
    assert.equal(net_utils.octets_in_string(str, 2, 7), false );
    done();
  })
})

describe('is_ip_literal', function () {
  it('ipv4 is_ip_literal', function (done) {
    assert.equal(net_utils.is_ip_literal('[127.0.0.0]'), true);
    assert.equal(net_utils.is_ip_literal('[127.0.0.1]'), true);
    assert.equal(net_utils.is_ip_literal('[127.1.0.255]'), true);
    assert.equal(net_utils.is_ip_literal('127.0.0.0'), false);
    assert.equal(net_utils.is_ip_literal('127.0.0.1'), false);
    assert.equal(net_utils.is_ip_literal('127.1.0.255'), false);

    done();
  })

  it('ipv6 is_ip_literal', function (done) {
    assert.equal(net_utils.is_ip_literal('[::5555:6666:7777:8888]'), true);
    assert.equal(net_utils.is_ip_literal('[1111::4444:5555:6666:7777:8888]'), true);
    assert.equal(net_utils.is_ip_literal('[2001:0:1234::C1C0:ABCD:876]'), true);
    assert.equal(net_utils.is_ip_literal('[IPv6:2607:fb90:4c28:f9e9:4ca2:2658:db85:f1a]'), true);
    assert.equal(net_utils.is_ip_literal('::5555:6666:7777:8888'), false);
    assert.equal(net_utils.is_ip_literal('1111::4444:5555:6666:7777:8888'), false);
    assert.equal(net_utils.is_ip_literal('2001:0:1234::C1C0:ABCD:876'), false);

    done();
  })
})

describe('is_local_ipv4', function () {
  it('127/8', function (done) {
    assert.equal(net_utils.is_local_ipv4('127.0.0.0'), true);
    assert.equal(net_utils.is_local_ipv4('127.0.0.1'), true);
    assert.equal(net_utils.is_local_ipv4('127.1.0.255'), true);

    done();
  })

  it('0/8', function (done) {
    assert.equal(net_utils.is_local_ipv4('0.0.0.1'), false);
    assert.equal(net_utils.is_local_ipv4('0.255.0.1'), false);
    assert.equal(net_utils.is_local_ipv4('1.255.0.1'), false);
    assert.equal(net_utils.is_local_ipv4('10.255.0.1'), false);
    done();
  })
})

describe('is_private_ipv4', function () {
  it('10/8', function (done) {
    assert.equal(net_utils.is_private_ipv4('10.0.0.0'), true);
    assert.equal(net_utils.is_private_ipv4('10.255.0.0'), true);
    assert.equal(net_utils.is_private_ipv4('9.255.0.0'), false);
    assert.equal(net_utils.is_private_ipv4('11.255.0.0'), false);
    done();
  })

  it('192.168/16', function (done) {
    assert.equal(net_utils.is_private_ipv4('192.168.0.0'), true);
    assert.equal(net_utils.is_private_ipv4('192.169.0.0'), false);
    assert.equal(net_utils.is_private_ipv4('192.167.0.0'), false);
    done();
  })

  it('172.16-31', function (done) {
    assert.equal(net_utils.is_private_ipv4('172.16.0.0'), true);
    assert.equal(net_utils.is_private_ipv4('172.20.0.0'), true);
    assert.equal(net_utils.is_private_ipv4('172.31.0.0'), true);
    assert.equal(net_utils.is_private_ipv4('172.15.0.0'), false);
    assert.equal(net_utils.is_private_ipv4('172.32.0.0'), false);
    done();
  })
})

describe('is_local_ipv6', function () {
  it('::', function (done) {
    assert.equal(net_utils.is_local_ipv6('::'), true);
    done();
  })

  it('::1', function (done) {
    assert.equal(net_utils.is_local_ipv6('::1'), true);
    assert.equal(net_utils.is_local_ipv6('0:0:0:0:0:0:0:1'), true);
    assert.equal(net_utils.is_local_ipv6(
      '0000:0000:0000:0000:0000:0000:0000:0001'), true);
    done();
  })

  it('fe80::/10', function (done) {
    assert.equal(net_utils.is_local_ipv6('fe80::'), true);
    assert.equal(net_utils.is_local_ipv6('fe80:'), false);
    assert.equal(net_utils.is_local_ipv6('fe8:'), false);
    assert.equal(net_utils.is_local_ipv6(':fe80:'), false);
    done();
  })

  it('fc80::/7', function (done) {
    assert.equal(net_utils.is_local_ipv6('fc00:'), true);
    assert.equal(net_utils.is_local_ipv6('fcff:'), true);

    // examples from https://en.wikipedia.org/wiki/Unique_local_address
    assert.equal(net_utils.is_local_ipv6('fde4:8dba:82e1::'), true);
    assert.equal(net_utils.is_local_ipv6('fde4:8dba:82e1:ffff::'), true);

    assert.equal(net_utils.is_local_ipv6('fd00:'), true);
    assert.equal(net_utils.is_local_ipv6('fdff:'), true);

    assert.equal(net_utils.is_local_ipv6('fb00:'), false);
    assert.equal(net_utils.is_local_ipv6('fe00:'), false);

    assert.equal(net_utils.is_local_ipv6('fe8:'), false);
    assert.equal(net_utils.is_local_ipv6(':fe80:'), false);
    done();
  })
})

const ip_fixtures = [
  [false , " 2001:0000:1234:0000:0000:C1C0:ABCD:0876  "],
  [false , " 2001:0000:1234:0000:0000:C1C0:ABCD:0876  0"],
  [false , " 2001:0000:1234:0000:0000:C1C0:ABCD:0876"],
  [false , " 2001:0:1234::C1C0:ABCD:876  "],
  [false , " 2001:0:1234::C1C0:ABCD:876"],
  [false , ""],
  [false , "':10.0.0.1"],
  [false , "---"],
  [false , "02001:0000:1234:0000:0000:C1C0:ABCD:0876"],
  [false , "1.2.3.4:1111:2222:3333:4444::5555"],
  [false , "1.2.3.4:1111:2222:3333::5555"],
  [false , "1.2.3.4:1111:2222::5555"],
  [false , "1.2.3.4:1111::5555"],
  [false , "1.2.3.4::"],
  [false , "1.2.3.4::5555"],
  [false , "1111"],
  [false , "11112222:3333:4444:5555:6666:1.2.3.4"],
  [false , "11112222:3333:4444:5555:6666:7777:8888"],
  [false , "1111:"],
  [false , "1111:1.2.3.4"],
  [false , "1111:2222"],
  [false , "1111:22223333:4444:5555:6666:1.2.3.4"],
  [false , "1111:22223333:4444:5555:6666:7777:8888"],
  [false , "1111:2222:"],
  [false , "1111:2222:1.2.3.4"],
  [false , "1111:2222:3333"],
  [false , "1111:2222:33334444:5555:6666:1.2.3.4"],
  [false , "1111:2222:33334444:5555:6666:7777:8888"],
  [false , "1111:2222:3333:"],
  [false , "1111:2222:3333:1.2.3.4"],
  [false , "1111:2222:3333:4444"],
  [false , "1111:2222:3333:44445555:6666:1.2.3.4"],
  [false , "1111:2222:3333:44445555:6666:7777:8888"],
  [false , "1111:2222:3333:4444:"],
  [false , "1111:2222:3333:4444:1.2.3.4"],
  [false , "1111:2222:3333:4444:5555"],
  [false , "1111:2222:3333:4444:55556666:1.2.3.4"],
  [false , "1111:2222:3333:4444:55556666:7777:8888"],
  [false , "1111:2222:3333:4444:5555:"],
  [false , "1111:2222:3333:4444:5555:1.2.3.4"],
  [false , "1111:2222:3333:4444:5555:6666"],
  [false , "1111:2222:3333:4444:5555:66661.2.3.4"],
  [false , "1111:2222:3333:4444:5555:66667777:8888"],
  [false , "1111:2222:3333:4444:5555:6666:"],
  [false , "1111:2222:3333:4444:5555:6666:00.00.00.00"],
  [false , "1111:2222:3333:4444:5555:6666:000.000.000.000"],
  [false , "1111:2222:3333:4444:5555:6666:1.2.3.4.5"],
  [false , "1111:2222:3333:4444:5555:6666:255.255.255255"],
  [false , "1111:2222:3333:4444:5555:6666:255.255255.255"],
  [false , "1111:2222:3333:4444:5555:6666:255255.255.255"],
  [false , "1111:2222:3333:4444:5555:6666:256.256.256.256"],
  [false , "1111:2222:3333:4444:5555:6666:7777"],
  [false , "1111:2222:3333:4444:5555:6666:77778888"],
  [false , "1111:2222:3333:4444:5555:6666:7777:"],
  [false , "1111:2222:3333:4444:5555:6666:7777:1.2.3.4"],
  [false , "1111:2222:3333:4444:5555:6666:7777:8888:"],
  [false , "1111:2222:3333:4444:5555:6666:7777:8888:1.2.3.4"],
  [false , "1111:2222:3333:4444:5555:6666:7777:8888:9999"],
  [false , "1111:2222:3333:4444:5555:6666:7777:8888::"],
  [false , "1111:2222:3333:4444:5555:6666:7777:::"],
  [false , "1111:2222:3333:4444:5555:6666::1.2.3.4"],
  [false , "1111:2222:3333:4444:5555:6666::8888:"],
  [false , "1111:2222:3333:4444:5555:6666:::"],
  [false , "1111:2222:3333:4444:5555:6666:::8888"],
  [false , "1111:2222:3333:4444:5555::7777:8888:"],
  [false , "1111:2222:3333:4444:5555::7777::"],
  [false , "1111:2222:3333:4444:5555::8888:"],
  [false , "1111:2222:3333:4444:5555:::"],
  [false , "1111:2222:3333:4444:5555:::1.2.3.4"],
  [false , "1111:2222:3333:4444:5555:::7777:8888"],
  [false , "1111:2222:3333:4444::5555:"],
  [false , "1111:2222:3333:4444::6666:7777:8888:"],
  [false , "1111:2222:3333:4444::6666:7777::"],
  [false , "1111:2222:3333:4444::6666::8888"],
  [false , "1111:2222:3333:4444::7777:8888:"],
  [false , "1111:2222:3333:4444::8888:"],
  [false , "1111:2222:3333:4444:::"],
  [false , "1111:2222:3333:4444:::6666:1.2.3.4"],
  [false , "1111:2222:3333:4444:::6666:7777:8888"],
  [false , "1111:2222:3333::5555:"],
  [false , "1111:2222:3333::5555:6666:7777:8888:"],
  [false , "1111:2222:3333::5555:6666:7777::"],
  [false , "1111:2222:3333::5555:6666::8888"],
  [false , "1111:2222:3333::5555::1.2.3.4"],
  [false , "1111:2222:3333::5555::7777:8888"],
  [false , "1111:2222:3333::6666:7777:8888:"],
  [false , "1111:2222:3333::7777:8888:"],
  [false , "1111:2222:3333::8888:"],
  [false , "1111:2222:3333:::"],
  [false , "1111:2222:3333:::5555:6666:1.2.3.4"],
  [false , "1111:2222:3333:::5555:6666:7777:8888"],
  [false , "1111:2222::4444:5555:6666:7777:8888:"],
  [false , "1111:2222::4444:5555:6666:7777::"],
  [false , "1111:2222::4444:5555:6666::8888"],
  [false , "1111:2222::4444:5555::1.2.3.4"],
  [false , "1111:2222::4444:5555::7777:8888"],
  [false , "1111:2222::4444::6666:1.2.3.4"],
  [false , "1111:2222::4444::6666:7777:8888"],
  [false , "1111:2222::5555:"],
  [false , "1111:2222::5555:6666:7777:8888:"],
  [false , "1111:2222::6666:7777:8888:"],
  [false , "1111:2222::7777:8888:"],
  [false , "1111:2222::8888:"],
  [false , "1111:2222:::"],
  [false , "1111:2222:::4444:5555:6666:1.2.3.4"],
  [false , "1111:2222:::4444:5555:6666:7777:8888"],
  [false , "1111::3333:4444:5555:6666:7777:8888:"],
  [false , "1111::3333:4444:5555:6666:7777::"],
  [false , "1111::3333:4444:5555:6666::8888"],
  [false , "1111::3333:4444:5555::1.2.3.4"],
  [false , "1111::3333:4444:5555::7777:8888"],
  [false , "1111::3333:4444::6666:1.2.3.4"],
  [false , "1111::3333:4444::6666:7777:8888"],
  [false , "1111::3333::5555:6666:1.2.3.4"],
  [false , "1111::3333::5555:6666:7777:8888"],
  [false , "1111::4444:5555:6666:7777:8888:"],
  [false , "1111::5555:"],
  [false , "1111::5555:6666:7777:8888:"],
  [false , "1111::6666:7777:8888:"],
  [false , "1111::7777:8888:"],
  [false , "1111::8888:"],
  [false , "1111:::"],
  [false , "1111:::3333:4444:5555:6666:1.2.3.4"],
  [false , "1111:::3333:4444:5555:6666:7777:8888"],
  [false , "123"],
  [false , "12345::6:7:8"],
  [false , "192.168.0.256"],
  [false , "192.168.256.0"],
  [false , "1:2:3:4:5:6:7:8:9"],
  [false , "1:2:3::4:5:6:7:8:9"],
  [false , "1:2:3::4:5::7:8"],
  [false , "1::1.2.256.4"],
  [false , "1::1.2.3.256"],
  [false , "1::1.2.3.300"],
  [false , "1::1.2.3.900"],
  [false , "1::1.2.300.4"],
  [false , "1::1.2.900.4"],
  [false , "1::1.256.3.4"],
  [false , "1::1.300.3.4"],
  [false , "1::1.900.3.4"],
  [false , "1::256.2.3.4"],
  [false , "1::260.2.3.4"],
  [false , "1::2::3"],
  [false , "1::300.2.3.4"],
  [false , "1::300.300.300.300"],
  [false , "1::3000.30.30.30"],
  [false , "1::400.2.3.4"],
  [false , "1::5:1.2.256.4"],
  [false , "1::5:1.2.3.256"],
  [false , "1::5:1.2.3.300"],
  [false , "1::5:1.2.3.900"],
  [false , "1::5:1.2.300.4"],
  [false , "1::5:1.2.900.4"],
  [false , "1::5:1.256.3.4"],
  [false , "1::5:1.300.3.4"],
  [false , "1::5:1.900.3.4"],
  [false , "1::5:256.2.3.4"],
  [false , "1::5:260.2.3.4"],
  [false , "1::5:300.2.3.4"],
  [false , "1::5:300.300.300.300"],
  [false , "1::5:3000.30.30.30"],
  [false , "1::5:400.2.3.4"],
  [false , "1::5:900.2.3.4"],
  [false , "1::900.2.3.4"],
  [false , "1:::3:4:5"],
  [false , "2001:0000:1234: 0000:0000:C1C0:ABCD:0876"],
  [false , "2001:0000:1234:0000:00001:C1C0:ABCD:0876"],
  [false , "2001:0000:1234:0000:0000:C1C0:ABCD:0876  0"],
  [false , "2001:1:1:1:1:1:255Z255X255Y255"],
  [false , "2001::FFD3::57ab"],
  [false , "2001:DB8:0:0:8:800:200C:417A:221"],
  [false , "2001:db8:85a3::8a2e:37023:7334"],
  [false , "2001:db8:85a3::8a2e:370k:7334"],
  [false , "255.256.255.255"],
  [false , "256.255.255.255"],
  [false , "3ffe:0b00:0000:0001:0000:0000:000a"],
  [false , "3ffe:b00::1::a"],
  [false , ":"],
  [false , ":1.2.3.4"],
  [false , ":1111:2222:3333:4444:5555:6666:1.2.3.4"],
  [false , ":1111:2222:3333:4444:5555:6666:7777:8888"],
  [false , ":1111:2222:3333:4444:5555:6666:7777::"],
  [false , ":1111:2222:3333:4444:5555:6666::"],
  [false , ":1111:2222:3333:4444:5555:6666::8888"],
  [false , ":1111:2222:3333:4444:5555::"],
  [false , ":1111:2222:3333:4444:5555::1.2.3.4"],
  [false , ":1111:2222:3333:4444:5555::7777:8888"],
  [false , ":1111:2222:3333:4444:5555::8888"],
  [false , ":1111:2222:3333:4444::"],
  [false , ":1111:2222:3333:4444::1.2.3.4"],
  [false , ":1111:2222:3333:4444::5555"],
  [false , ":1111:2222:3333:4444::6666:1.2.3.4"],
  [false , ":1111:2222:3333:4444::6666:7777:8888"],
  [false , ":1111:2222:3333:4444::7777:8888"],
  [false , ":1111:2222:3333:4444::8888"],
  [false , ":1111:2222:3333::"],
  [false , ":1111:2222:3333::1.2.3.4"],
  [false , ":1111:2222:3333::5555"],
  [false , ":1111:2222:3333::5555:6666:1.2.3.4"],
  [false , ":1111:2222:3333::5555:6666:7777:8888"],
  [false , ":1111:2222:3333::6666:1.2.3.4"],
  [false , ":1111:2222:3333::6666:7777:8888"],
  [false , ":1111:2222:3333::7777:8888"],
  [false , ":1111:2222:3333::8888"],
  [false , ":1111:2222::"],
  [false , ":1111:2222::1.2.3.4"],
  [false , ":1111:2222::4444:5555:6666:1.2.3.4"],
  [false , ":1111:2222::4444:5555:6666:7777:8888"],
  [false , ":1111:2222::5555"],
  [false , ":1111:2222::5555:6666:1.2.3.4"],
  [false , ":1111:2222::5555:6666:7777:8888"],
  [false , ":1111:2222::6666:1.2.3.4"],
  [false , ":1111:2222::6666:7777:8888"],
  [false , ":1111:2222::7777:8888"],
  [false , ":1111:2222::8888"],
  [false , ":1111::"],
  [false , ":1111::1.2.3.4"],
  [false , ":1111::3333:4444:5555:6666:1.2.3.4"],
  [false , ":1111::3333:4444:5555:6666:7777:8888"],
  [false , ":1111::4444:5555:6666:1.2.3.4"],
  [false , ":1111::4444:5555:6666:7777:8888"],
  [false , ":1111::5555"],
  [false , ":1111::5555:6666:1.2.3.4"],
  [false , ":1111::5555:6666:7777:8888"],
  [false , ":1111::6666:1.2.3.4"],
  [false , ":1111::6666:7777:8888"],
  [false , ":1111::7777:8888"],
  [false , ":1111::8888"],
  [false , ":2222:3333:4444:5555:6666:1.2.3.4"],
  [false , ":2222:3333:4444:5555:6666:7777:8888"],
  [false , ":3333:4444:5555:6666:1.2.3.4"],
  [false , ":3333:4444:5555:6666:7777:8888"],
  [false , ":4444:5555:6666:1.2.3.4"],
  [false , ":4444:5555:6666:7777:8888"],
  [false , ":5555:6666:1.2.3.4"],
  [false , ":5555:6666:7777:8888"],
  [false , ":6666:1.2.3.4"],
  [false , ":6666:7777:8888"],
  [false , ":7777:8888"],
  [false , ":8888"],
  [false , "::."],
  [false , "::.."],
  [false , "::..."],
  [false , "::...4"],
  [false , "::..3."],
  [false , "::..3.4"],
  [false , "::.2.."],
  [false , "::.2.3."],
  [false , "::.2.3.4"],
  [false , "::1..."],
  [false , "::1.2.."],
  [false , "::1.2.256.4"],
  [false , "::1.2.3."],
  [false , "::1.2.3.256"],
  [false , "::1.2.3.300"],
  [false , "::1.2.3.900"],
  [false , "::1.2.300.4"],
  [false , "::1.2.900.4"],
  [false , "::1.256.3.4"],
  [false , "::1.300.3.4"],
  [false , "::1.900.3.4"],
  [false , "::1111:2222:3333:4444:5555:6666::"],
  [false , "::2222:3333:4444:5555:6666:7777:1.2.3.4"],
  [false , "::2222:3333:4444:5555:6666:7777:8888:"],
  [false , "::2222:3333:4444:5555:6666:7777:8888:9999"],
  [false , "::2222:3333:4444:5555:7777:8888::"],
  [false , "::2222:3333:4444:5555:7777::8888"],
  [false , "::2222:3333:4444:5555::1.2.3.4"],
  [false , "::2222:3333:4444:5555::7777:8888"],
  [false , "::2222:3333:4444::6666:1.2.3.4"],
  [false , "::2222:3333:4444::6666:7777:8888"],
  [false , "::2222:3333::5555:6666:1.2.3.4"],
  [false , "::2222:3333::5555:6666:7777:8888"],
  [false , "::2222::4444:5555:6666:1.2.3.4"],
  [false , "::2222::4444:5555:6666:7777:8888"],
  [false , "::256.2.3.4"],
  [false , "::260.2.3.4"],
  [false , "::300.2.3.4"],
  [false , "::300.300.300.300"],
  [false , "::3000.30.30.30"],
  [false , "::3333:4444:5555:6666:7777:8888:"],
  [false , "::400.2.3.4"],
  [false , "::4444:5555:6666:7777:8888:"],
  [false , "::5555:"],
  [false , "::5555:6666:7777:8888:"],
  [false , "::6666:7777:8888:"],
  [false , "::7777:8888:"],
  [false , "::8888:"],
  [false , "::900.2.3.4"],
  [false , ":::"],
  [false , ":::1.2.3.4"],
  [false , ":::2222:3333:4444:5555:6666:1.2.3.4"],
  [false , ":::2222:3333:4444:5555:6666:7777:8888"],
  [false , ":::3333:4444:5555:6666:7777:8888"],
  [false , ":::4444:5555:6666:1.2.3.4"],
  [false , ":::4444:5555:6666:7777:8888"],
  [false , ":::5555"],
  [false , ":::5555:6666:1.2.3.4"],
  [false , ":::5555:6666:7777:8888"],
  [false , ":::6666:1.2.3.4"],
  [false , ":::6666:7777:8888"],
  [false , ":::7777:8888"],
  [false , ":::8888"],
  [false , "::ffff:192x168.1.26"],
  [false , "::ffff:2.3.4"],
  [false , "::ffff:257.1.2.3"],
  [false , "FF01::101::2"],
  [false , "FF02:0000:0000:0000:0000:0000:0000:0000:0001"],
  [false , "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:1.2.3.4"],
  [false , "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX"],
  [false , "fe80:0000:0000:0000:0204:61ff:254.157.241.086"],
  [false , "fe80::4413:c8ae:2821:5852%10"],
  [false , "ldkfj"],
  [false , "mydomain.com"],
  [false , "test.mydomain.com"],
  [true , "0000:0000:0000:0000:0000:0000:0000:0000"],
  [true , "0000:0000:0000:0000:0000:0000:0000:0001"],
  [true , "0:0:0:0:0:0:0:0"],
  [true , "0:0:0:0:0:0:0:1"],
  [true , "0:0:0:0:0:0:0::"],
  [true , "0:0:0:0:0:0:13.1.68.3"],
  [true , "0:0:0:0:0:0::"],
  [true , "0:0:0:0:0::"],
  [true , "0:0:0:0:0:FFFF:129.144.52.38"],
  [true , "0:0:0:0::"],
  [true , "0:0:0::"],
  [true , "0:0::"],
  [true , "0::"],
  [true , "0:a:b:c:d:e:f::"],
  [true , "1.2.3.4"],
  [true , "1111:2222:3333:4444:5555:6666:123.123.123.123"],
  [true , "1111:2222:3333:4444:5555:6666:7777:8888"],
  [true , "1111:2222:3333:4444:5555:6666:7777::"],
  [true , "1111:2222:3333:4444:5555:6666::"],
  [true , "1111:2222:3333:4444:5555:6666::8888"],
  [true , "1111:2222:3333:4444:5555::"],
  [true , "1111:2222:3333:4444:5555::123.123.123.123"],
  [true , "1111:2222:3333:4444:5555::7777:8888"],
  [true , "1111:2222:3333:4444:5555::8888"],
  [true , "1111:2222:3333:4444::"],
  [true , "1111:2222:3333:4444::123.123.123.123"],
  [true , "1111:2222:3333:4444::6666:123.123.123.123"],
  [true , "1111:2222:3333:4444::6666:7777:8888"],
  [true , "1111:2222:3333:4444::7777:8888"],
  [true , "1111:2222:3333:4444::8888"],
  [true , "1111:2222:3333::"],
  [true , "1111:2222:3333::123.123.123.123"],
  [true , "1111:2222:3333::5555:6666:123.123.123.123"],
  [true , "1111:2222:3333::5555:6666:7777:8888"],
  [true , "1111:2222:3333::6666:123.123.123.123"],
  [true , "1111:2222:3333::6666:7777:8888"],
  [true , "1111:2222:3333::7777:8888"],
  [true , "1111:2222:3333::8888"],
  [true , "1111:2222::"],
  [true , "1111:2222::123.123.123.123"],
  [true , "1111:2222::4444:5555:6666:123.123.123.123"],
  [true , "1111:2222::4444:5555:6666:7777:8888"],
  [true , "1111:2222::5555:6666:123.123.123.123"],
  [true , "1111:2222::5555:6666:7777:8888"],
  [true , "1111:2222::6666:123.123.123.123"],
  [true , "1111:2222::6666:7777:8888"],
  [true , "1111:2222::7777:8888"],
  [true , "1111:2222::8888"],
  [true , "1111::"],
  [true , "1111::123.123.123.123"],
  [true , "1111::3333:4444:5555:6666:123.123.123.123"],
  [true , "1111::3333:4444:5555:6666:7777:8888"],
  [true , "1111::4444:5555:6666:123.123.123.123"],
  [true , "1111::4444:5555:6666:7777:8888"],
  [true , "1111::5555:6666:123.123.123.123"],
  [true , "1111::5555:6666:7777:8888"],
  [true , "1111::6666:123.123.123.123"],
  [true , "1111::6666:7777:8888"],
  [true , "1111::7777:8888"],
  [true , "1111::8888"],
  [true , "123.23.34.2"],
  [true , "172.26.168.134"],
  [true , "192.168.0.0"],
  [true , "192.168.128.255"],
  [true , "1:2:3:4:5:6:1.2.3.4"],
  [true , "1:2:3:4:5:6:7:8"],
  [true , "1:2:3:4:5:6::"],
  [true , "1:2:3:4:5:6::8"],
  [true , "1:2:3:4:5::"],
  [true , "1:2:3:4:5::1.2.3.4"],
  [true , "1:2:3:4:5::7:8"],
  [true , "1:2:3:4:5::8"],
  [true , "1:2:3:4::"],
  [true , "1:2:3:4::1.2.3.4"],
  [true , "1:2:3:4::5:1.2.3.4"],
  [true , "1:2:3:4::7:8"],
  [true , "1:2:3:4::8"],
  [true , "1:2:3::"],
  [true , "1:2:3::1.2.3.4"],
  [true , "1:2:3::5:1.2.3.4"],
  [true , "1:2:3::7:8"],
  [true , "1:2:3::8"],
  [true , "1:2::"],
  [true , "1:2::1.2.3.4"],
  [true , "1:2::5:1.2.3.4"],
  [true , "1:2::7:8"],
  [true , "1:2::8"],
  [true , "1::"],
  [true , "1::1.2.3.4"],
  [true , "1::2:3"],
  [true , "1::2:3:4"],
  [true , "1::2:3:4:5"],
  [true , "1::2:3:4:5:6"],
  [true , "1::2:3:4:5:6:7"],
  [true , "1::5:1.2.3.4"],
  [true , "1::5:11.22.33.44"],
  [true , "1::7:8"],
  [true , "1::8"],
  [true , "2001:0000:1234:0000:0000:C1C0:ABCD:0876"],
  [true , "2001:0:1234::C1C0:ABCD:876"],
  [true , "2001:0db8:0000:0000:0000:0000:1428:57ab"],
  [true , "2001:0db8:0000:0000:0000::1428:57ab"],
  [true , "2001:0db8:0:0:0:0:1428:57ab"],
  [true , "2001:0db8:0:0::1428:57ab"],
  [true , "2001:0db8:1234:0000:0000:0000:0000:0000"],
  [true , "2001:0db8:1234::"],
  [true , "2001:0db8:1234:ffff:ffff:ffff:ffff:ffff"],
  [true , "2001:0db8:85a3:0000:0000:8a2e:0370:7334"],
  [true , "2001:0db8::1428:57ab"],
  [true , "2001:2:3:4:5:6:7:134"],
  [true , "2001:DB8:0:0:8:800:200C:417A"],
  [true , "2001:DB8::8:800:200C:417A"],
  [true , "2001:db8:85a3:0:0:8a2e:370:7334"],
  [true , "2001:db8:85a3::8a2e:370:7334"],
  [true , "2001:db8::"],
  [true , "2001:db8::1428:57ab"],
  [true , "2001:db8:a::123"],
  [true , "2002::"],
  [true , "2::10"],
  [true , "3ffe:0b00:0000:0000:0001:0000:0000:000a"],
  [true , "3ffe:b00::1:0:0:a"],
  [true , "::"],
  [true , "::0"],
  [true , "::0:0"],
  [true , "::0:0:0"],
  [true , "::0:0:0:0"],
  [true , "::0:0:0:0:0"],
  [true , "::0:0:0:0:0:0"],
  [true , "::0:0:0:0:0:0:0"],
  [true , "::0:a:b:c:d:e:f"],
  [true , "::1"],
  [true , "::123.123.123.123"],
  [true , "::13.1.68.3"],
  [true , "::2222:3333:4444:5555:6666:123.123.123.123"],
  [true , "::2222:3333:4444:5555:6666:7777:8888"],
  [true , "::2:3"],
  [true , "::2:3:4"],
  [true , "::2:3:4:5"],
  [true , "::2:3:4:5:6"],
  [true , "::2:3:4:5:6:7"],
  [true , "::2:3:4:5:6:7:8"],
  [true , "::3333:4444:5555:6666:7777:8888"],
  [true , "::4444:5555:6666:123.123.123.123"],
  [true , "::4444:5555:6666:7777:8888"],
  [true , "::5555:6666:123.123.123.123"],
  [true , "::5555:6666:7777:8888"],
  [true , "::6666:123.123.123.123"],
  [true , "::6666:7777:8888"],
  [true , "::7777:8888"],
  [true , "::8"],
  [true , "::8888"],
  [true , "::FFFF:129.144.52.38"],
  [true , "::ffff:0:0"],
  [true , "::ffff:0c22:384e"],
  [true , "::ffff:12.34.56.78"],
  [true , "::ffff:192.0.2.128"],
  [true , "::ffff:192.168.1.1"],
  [true , "::ffff:192.168.1.26"],
  [true , "::ffff:c000:280"],
  [true , "FF01:0:0:0:0:0:0:101"],
  [true , "FF01::101"],
  [true , "FF02:0000:0000:0000:0000:0000:0000:0001"],
  [true , "FF02::1"],
  [true , "a:b:c:d:e:f:0::"],
  [true , "fe80:0000:0000:0000:0204:61ff:fe9d:f156"],
  [true , "fe80:0:0:0:204:61ff:254.157.241.86"],
  [true , "fe80:0:0:0:204:61ff:fe9d:f156"],
  [true , "fe80::"],
  [true , "fe80::1"],
  [true , "fe80::204:61ff:254.157.241.86"],
  [true , "fe80::204:61ff:fe9d:f156"],
  [true , "fe80::217:f2ff:254.7.237.98"],
  [true , "fe80::217:f2ff:fe07:ed62"],
  [true , "ff02::1"]
];

describe('get_ipany_re', function () {
  it('IPv6, Prefix', function (done) {
    // for x-*-ip headers
    // it must fail as of not valide
    assert.ok(!net.isIPv6('IPv6:2001:db8:85a3::8a2e:370:7334'));
    // must okay!
    assert.ok(net.isIPv6('2001:db8:85a3::8a2e:370:7334'));
    done();
  })

  it('IP fixtures check', function (done) {
    for (const i in ip_fixtures) {
      const match = net_utils.get_ipany_re('^','$').test(ip_fixtures[i][1]);
      // console.log('IP:', `'${ip_fixtures[i][1]}'` , 'Expected:', ip_fixtures[i][0] , 'Match:' , match);
      assert.ok((match===ip_fixtures[i][0]), `${ip_fixtures[i][1]} - Expected: ${ip_fixtures[i][0]} - Match: ${match}`);
    }
    done();
  })

  it('IPv4, bare', function (done) {
    // for x-*-ip headers
    const match = net_utils.get_ipany_re().exec('127.0.0.1');
    assert.equal(match[1], '127.0.0.1');
    assert.equal(match.length, 2);
    done();
  })

  it('IPv4, Received header, parens', function (done) {
    const received_re = net_utils.get_ipany_re('^Received:.*?[\\[\\(]', '[\\]\\)]');
    const match = received_re.exec('Received: from unknown (HELO mail.theartfarm.com) (127.0.0.30) by mail.theartfarm.com with SMTP; 5 Sep 2015 14:29:00 -0000');
    assert.equal(match[1], '127.0.0.30');
    assert.equal(match.length, 2);
    done();
  })

  it('IPv4, Received header, bracketed, expedia', function (done) {
    const received_header = 'Received: from mta2.expediamail.com (mta2.expediamail.com [66.231.89.19]) by mail.theartfarm.com (Haraka/2.6.2-toaster) with ESMTPS id C669CF18-1C1C-484C-8A5B-A89088B048CB.1 envelope-from <bounce-857_HTML-202764435-1098240-260085-60@bounce.global.expediamail.com> (version=TLSv1/SSLv3 cipher=AES256-SHA verify=NO); Sat, 05 Sep 2015 07:28:57 -0700';
    const received_re = net_utils.get_ipany_re('^Received:.*?[\\[\\(]', '[\\]\\)]');
    const match = received_re.exec(received_header);
    assert.equal(match[1], '66.231.89.19');
    assert.equal(match.length, 2);
    done();
  })

  it('IPv4, Received header, bracketed, github', function (done) {
    const received_re = net_utils.get_ipany_re('^Received:.*?[\\[\\(]', '[\\]\\)]');
    const match = received_re.exec('Received: from github-smtp2a-ext-cp1-prd.iad.github.net (github-smtp2-ext5.iad.github.net [192.30.252.196])');
    assert.equal(match[1], '192.30.252.196');
    assert.equal(match.length, 2);
    done();
  })

  it('IPv6, Received header, bracketed', function (done) {
    const received_header = 'Received: from ?IPv6:2601:184:c001:5cf7:a53f:baf7:aaf3:bce7? ([2601:184:c001:5cf7:a53f:baf7:aaf3:bce7])';
    const received_re = net_utils.get_ipany_re('^Received:.*?[\\[\\(]', '[\\]\\)]');
    const match = received_re.exec(received_header);
    assert.equal(match[1], '2601:184:c001:5cf7:a53f:baf7:aaf3:bce7');
    assert.equal(match.length, 2);
    done();
  })

  it('IPv6, Received header, bracketed, IPv6 prefix', function (done) {
    const received_re = net_utils.get_ipany_re('^Received:.*?[\\[\\(](?:IPv6:)?', '[\\]\\)]');
    const match = received_re.exec('Received: from hub.freebsd.org (hub.freebsd.org [IPv6:2001:1900:2254:206c::16:88])');
    assert.equal(match[1], '2001:1900:2254:206c::16:88');
    assert.equal(match.length, 2);
    done();
  })

  it('IPv6, folded Received header, bracketed, IPv6 prefix', function (done) {
    // note the use of [\s\S], '.' doesn't match newlines in JS regexp
    const received_re = net_utils.get_ipany_re('^Received:[\\s\\S]*?[\\[\\(](?:IPv6:)?', '[\\]\\)]');
    const match = received_re.exec('Received: from freefall.freebsd.org (freefall.freebsd.org\r\n [IPv6:2001:1900:2254:206c::16:87])');
    if (match) {
      assert.equal(match[1], '2001:1900:2254:206c::16:87');
      assert.equal(match.length, 2);
    }
    done();
  })

  it('IPv6, Received header, bracketed, IPv6 prefix, localhost compressed', function (done) {
    const received_re = net_utils.get_ipany_re('^Received:.*?[\\[\\(](?:IPv6:)?', '[\\]\\)]');
    const match = received_re.exec('Received: from ietfa.amsl.com (localhost [IPv6:::1])');
    assert.equal(match[1], '::1');
    assert.equal(match.length, 2);
    done();
  })

  it('IPv6 bogus', function (done) {
    const is_bogus = net_utils.ipv6_bogus('::192.41.13.251'); // From https://github.com/haraka/Haraka/issues/2763
    assert.equal(is_bogus, true);
    done();
  })
})

describe('get_ips_by_host', function () {
  const tests = {
    'servedby.tnpi.net': [
      '192.48.85.146',
      '192.48.85.147',
      '192.48.85.148',
      '192.48.85.149',
      '2607:f060:b008:feed::2'
    ],
    'localhost.simerson.net': [ '127.0.0.1', '::1' ]
  }

  for (const t in tests) {

    it(`get_ips_by_host, ${t}`, function (done) {
      this.timeout(4000)
      net_utils.get_ips_by_host(t, function (err, res) {
        if (err && err.length) {
          console.error(err);
        }
        assert.deepEqual(err, []);
        assert.deepEqual(res.sort(), tests[t].sort());
        done();
      });
    })

    it(`get_ips_by_host, promise, ${t}`, async function () {
      try {
        const res = await net_utils.get_ips_by_host(t)
        assert.deepEqual(res.sort(), tests[t].sort());
      }
      catch (e) {
        console.error(e);
      }
    })
  }
})

function _check_list (done, list, ip, res) {
  assert.equal(net_utils.ip_in_list(list, ip), res);  // keys of object
  assert.equal(net_utils.ip_in_list(Object.keys(list), ip), res);  // array
  done();
}

describe('ip_in_list', function () {
  it('domain.com', function (done) {
    _check_list(done, { 'domain.com': undefined }, 'domain.com', true);
  })

  it('foo.com', function (done) {
    _check_list(done, { }, 'foo.com', false);
  })

  it('1.2.3.4', function (done) {
    _check_list(done, { '1.2.3.4': undefined }, '1.2.3.4', true);
  })

  it('1.2.3.4/32', function (done) {
    _check_list(done, { '1.2.3.4/32': undefined }, '1.2.3.4', true);
  })

  it('1.2.0.0/16 <-> 1.2.3.4', function (done) {
    _check_list(done, { '1.2.0.0/16': undefined }, '1.2.3.4', true);
  })

  it('1.2.0.0/16 <-> 5.6.7.8', function (done) {
    _check_list(done, { '1.2.0.0/16': undefined }, '5.6.7.8', false);
  })

  it('0000:0000:0000:0000:0000:0000:0000:0001', function (done) {
    _check_list(done, { '0000:0000:0000:0000:0000:0000:0000:0001': undefined }, '0000:0000:0000:0000:0000:0000:0000:0001', true);
  })

  it('0:0:0:0:0:0:0:1', function (done) {
    _check_list(done, { '0:0:0:0:0:0:0:1': undefined }, '0000:0000:0000:0000:0000:0000:0000:0001', true);
  })

  it('1.2 (bad config)', function (done) {
    _check_list(done, { '1.2': undefined }, '1.2.3.4', false);
  })

  it('1.2.3.4/ (mask ignored)', function (done) {
    _check_list(done, { '1.2.3.4/': undefined }, '1.2.3.4', true);
  })

  it('1.2.3.4/gr (mask ignored)', function (done) {
    _check_list(done, { '1.2.3.4/gr': undefined }, '1.2.3.4', true);
  })

  it('1.2.3.4/400 (mask read as 400 bits)', function (done) {
    _check_list(done, { '1.2.3.4/400': undefined }, '1.2.3.4', true);
  })
})

describe('get_primary_host_name', function () {
  beforeEach(function (done) {
    this.net_utils = require('../index');
    this.net_utils.config = this.net_utils.config.module_config(path.resolve('test'));
    done();
  })

  it('with me config', function (done) {
    assert.equal(this.net_utils.get_primary_host_name(), 'test-hostname');
    done();
  })

  it('without me config', function (done) {
    this.net_utils.config = this.net_utils.config.module_config(path.resolve('doesnt-exist'));
    assert.equal(this.net_utils.get_primary_host_name(), os.hostname());
    done();
  })
})

describe('on_local_interface', function () {
  beforeEach(function (done) {
    this.net_utils = require('../index');
    this.net_utils.config = this.net_utils.config.module_config(path.resolve('test'));
    done();
  })

  it('localhost 127.0.0.1', function (done) {
    assert.equal(this.net_utils.on_local_interface('127.0.0.1'), true);
    done();
  })

  it('multicast 1.1.1.1', function (done) {
    assert.equal(this.net_utils.on_local_interface('1.1.1.1'), false);
    done();
  })

  it('ipv6 localhost ::1', function (done) {
    const r = this.net_utils.on_local_interface('::1');
    if (r) {
      assert.equal(r, true);
    }
    done();
  })
})

describe('get_mx', function () {
  beforeEach(function (done) {
    this.net_utils = require('../index');
    done();
  })

  const validCases = {
    'tnpi.net'     : 'mail.theartfarm.com',
    'matt@tnpi.net': 'mail.theartfarm.com',
    'matt.simerson@gmail.com': /google.com/,
    'example.com'  : '',
  }

  function checkValid (c, mxlist) {
    if ('string' === typeof c) {
      assert.equal(mxlist[0].exchange, c);
    }
    else {
      assert.ok(c.test(mxlist[0].exchange))
    }
  }

  for (const c in validCases) {
    it(`gets MX records for ${c}`, function (done) {
      this.timeout(3000)
      this.net_utils.get_mx(c, (err, mxlist) => {
        if (err) console.error(err)
        assert.ifError(err);
        // assert.ok(mxlist.length);
        checkValid(validCases[c], mxlist)
        done()
      })
    })

    it(`awaits MX records for ${c}`, async function () {
      this.timeout(3000)
      const mxlist = await this.net_utils.get_mx(c)
      // assert.ok(mxlist.length);
      checkValid(validCases[c], mxlist)
    })
  }

  // macOS: ENODATA, win: ENOTOUND, ubuntu: ESERVFAIL
  const noDnsRe = /queryMx (ENODATA|ENOTFOUND|ESERVFAIL)|Cannot convert name to ASCII/
  const invalidCases = {
    'invalid': noDnsRe,
    'gmail.xn--com-0da': noDnsRe,
  }

  for (const c in invalidCases) {
    it(`cb does not crash on invalid name: ${c}`, function () {
      this.net_utils.get_mx(c, (err, mxlist) => {
        // console.error(err)
        assert.equal(mxlist.length, 0)
        assert.equal(noDnsRe.test(err.message), true)
      })
    })

    it(`async does not crash on invalid name: ${c}`, async function () {
      try {
        const mxlist = await this.net_utils.get_mx(c)
        assert.equal(mxlist.length, 0)
      }
      catch (err) {
        // console.error(err)
        assert.equal(noDnsRe.test(err.message), true)
      }
    })
  }
})
