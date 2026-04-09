const assert = require('node:assert')
const { beforeEach, describe, it } = require('node:test')

describe('get_mx', () => {
  let net_utils

  beforeEach(() => {
    net_utils = require('../index')
  })

  const validCases = {
    'tnpi.net': 'mail.theartfarm.com',
    'matt@tnpi.net': 'mail.theartfarm.com',
    'matt.simerson@gmail.com': /google.com/,
    'example.com': '',
    'no-mx.haraka.tnpi.net': '192.0.99.5',
    'bad-mx.haraka.tnpi.net': /99/,
    'über.haraka.tnpi.net': 'no-mx.haraka.tnpi.net',
  }

  function checkValid(c, mxlist) {
    try {
      if ('string' === typeof c) {
        assert.equal(mxlist[0].exchange, c)
      } else {
        assert.ok(c.test(mxlist[0].exchange))
      }
    } catch (err) {
      console.error(err)
    }
  }

  for (const c in validCases) {
    it(
      `gets MX records for ${c}`,
      { timeout: 12000 },
      () =>
        new Promise((resolve) => {
          net_utils.get_mx(c, (err, mxlist) => {
            if (err) console.error(err)
            assert.ifError(err)
            checkValid(validCases[c], mxlist)
            resolve()
          })
        }),
    )

    it(`awaits MX records for ${c}`, { timeout: 12000 }, async () => {
      const mxlist = await net_utils.get_mx(c)
      checkValid(validCases[c], mxlist)
    })
  }

  // macOS: ENODATA, win: ENOTOUND, ubuntu: ESERVFAIL
  const invalidCases = {
    invalid: /queryMx (ENODATA|ENOTFOUND|ESERVFAIL) invalid/,
    'gmail.xn--com-0da': /(ENOTFOUND|ENOMEM|Cannot convert name to ASCII)/,
    'non-exist.haraka.tnpi.net': /ignore/,
    'haraka.non-exist': /ignore/,
  }

  function checkInvalid(expected, actual) {
    if ('string' === typeof expected) {
      assert.strictEqual(actual, expected)
    } else {
      assert.equal(expected.test(actual), true)
    }
  }

  for (const c in invalidCases) {
    it(`cb does not crash on invalid name: ${c}`, () => {
      net_utils.get_mx(c, (err, mxlist) => {
        if (err) checkInvalid(invalidCases[c], err.message)
        assert.equal(mxlist.length, 0)
      })
    })

    it(`async does not crash on invalid name: ${c}`, async () => {
      try {
        const mxlist = await net_utils.get_mx(c)
        assert.equal(mxlist.length, 0)
      } catch (err) {
        checkInvalid(invalidCases[c], err.message)
      }
    })
  }

  describe('resolve_mx_hosts', () => {
    let nu

    beforeEach(() => {
      nu = require('../index')
    })

    const expectedResolvedMx = [
      {
        exchange: '2605:ae00:329::6',
        priority: 10,
        from_dns: 'mail.theartfarm.com',
      },
      {
        exchange: '66.128.51.165',
        priority: 10,
        from_dns: 'mail.theartfarm.com',
      },
    ]

    it('resolves mx hosts to IPs, tnpi.net', { timeout: 12000 }, async () => {
      const r = await nu.resolve_mx_hosts([
        { exchange: 'mail.theartfarm.com', priority: 10, from_dns: 'tnpi.net' },
      ])
      assert.deepEqual(r, expectedResolvedMx)
    })

    it('resolves mx hosts to IPs, gmail.com', { timeout: 12000 }, async () => {
      const mxes = await nu.get_mx('gmail.com')
      assert.equal(mxes.length, 5)
      const r = await nu.resolve_mx_hosts(mxes)
      assert.equal(r.length, 10)
    })

    it('returns IPs as is', async () => {
      const r = await nu.resolve_mx_hosts(expectedResolvedMx)
      assert.deepEqual(r, expectedResolvedMx)
    })

    it('returns sockets as-is', async () => {
      const r = await nu.resolve_mx_hosts([{ path: '/var/run/sock' }])
      assert.deepEqual(r, [{ path: '/var/run/sock' }])
    })

    it('resolve_mx_hosts, gmail.com', { timeout: 12000 }, async () => {
      const mxes = await nu.get_mx('gmail.com')
      const r = await nu.resolve_mx_hosts(mxes)
      assert.equal(r.length, 10)
    })

    it('resolve_mx_hosts, yahoo.com', { timeout: 12000 }, async () => {
      const mxes = await nu.get_mx('yahoo.com')
      const r = await nu.resolve_mx_hosts([mxes[0]])
      assert.equal(r.length, 8)
    })
  })

  describe('get_implicit_mx', () => {
    let nu

    beforeEach(() => {
      nu = require('../index')
    })

    it('harakamail.com', { timeout: 5000 }, async () => {
      const mf = await nu.get_implicit_mx('harakamail.com')
      assert.equal(mf.length, 1)
    })

    it('mx.theartfarm.com', { timeout: 5000 }, async () => {
      const mf = await nu.get_implicit_mx('mx.theartfarm.com')
      assert.equal(mf.length, 0)
    })

    it(
      'resolve-fail-definitive.josef-froehle.de',
      { timeout: 5000 },
      async () => {
        const mf = await nu.get_implicit_mx(
          'resolve-fail-definitive.josef-froehle.de',
        )
        assert.equal(mf.length, 0)
      },
    )

    it('resolve-fail-a.josef-froehle.de', { timeout: 5000 }, async () => {
      const mf = await nu.get_implicit_mx('resolve-fail-a.josef-froehle.de')
      assert.equal(mf.length, 1)
    })

    it('resolve-fail-aaaa.josef-froehle.de', { timeout: 5000 }, async () => {
      const mf = await nu.get_implicit_mx('resolve-fail-aaaa.josef-froehle.de')
      assert.equal(mf.length, 0)
    })
  })
})
