const assert = require('node:assert')
const { beforeEach, describe, it } = require('node:test')

process.env.NODE_ENV = 'test'

describe('HarakaMx', () => {
  let nu
  beforeEach(() => {
    nu = require('../index')
  })

  describe('fromObject', () => {
    it('accepts an object', () => {
      assert.deepEqual(
        new nu.HarakaMx({
          from_dns: 'example.com',
          exchange: '.',
          priority: 0,
        }),
        { from_dns: 'example.com', exchange: '.', priority: 0 },
      )
    })

    it('sets default priority to 0', () => {
      assert.deepEqual(new nu.HarakaMx({ exchange: '.' }), {
        exchange: '.',
        priority: 0,
      })
    })

    it('if optional domain provided, sets from_dns', () => {
      assert.deepEqual(new nu.HarakaMx({ exchange: '.' }, 'example.com'), {
        from_dns: 'example.com',
        exchange: '.',
        priority: 0,
      })
    })
  })

  describe('fromString', () => {
    it('parses a hostname', () => {
      assert.deepEqual(new nu.HarakaMx('mail.example.com'), {
        exchange: 'mail.example.com',
        priority: 0,
      })
    })

    it('parses a hostname:port', () => {
      assert.deepEqual(new nu.HarakaMx('mail.example.com:25'), {
        exchange: 'mail.example.com',
        port: 25,
        priority: 0,
      })
    })

    it('parses an IPv4', () => {
      assert.deepEqual(new nu.HarakaMx('192.0.2.1'), {
        exchange: '192.0.2.1',
        priority: 0,
      })
    })

    it('parses an IPv4:port', () => {
      assert.deepEqual(new nu.HarakaMx('192.0.2.1:25'), {
        exchange: '192.0.2.1',
        port: 25,
        priority: 0,
      })
    })

    it('parses an IPv6', () => {
      assert.deepEqual(new nu.HarakaMx('2001:db8::1'), {
        exchange: '2001:db8::1',
        priority: 0,
      })
    })

    it('parses an IPv6:port', () => {
      assert.deepEqual(new nu.HarakaMx('2001:db8::1:25'), {
        exchange: '2001:db8::1',
        port: 25,
        priority: 0,
      })
    })

    it('parses an [IPv6]:port', () => {
      assert.deepEqual(new nu.HarakaMx('[2001:db8::1]:25'), {
        exchange: '2001:db8::1',
        port: 25,
        priority: 0,
      })
    })
  })

  describe('fromUrl', () => {
    it('parses simple URIs', () => {
      assert.deepEqual(new nu.HarakaMx('smtp://192.0.2.2'), {
        exchange: '192.0.2.2',
        priority: 0,
      })

      assert.deepEqual(new nu.HarakaMx('smtp://[2001:db8::1]:25'), {
        exchange: '[2001:db8::1]',
        port: 25,
        priority: 0,
      })
    })

    it('parses more complex URIs', () => {
      assert.deepEqual(
        new nu.HarakaMx('smtp://authUser:sekretPass@[2001:db8::1]'),
        {
          exchange: '[2001:db8::1]',
          priority: 0,
          auth_pass: 'sekretPass',
          auth_user: 'authUser',
        },
      )

      assert.deepEqual(
        new nu.HarakaMx('lmtp://authUser:sekretPass@[2001:db8::1]:25'),
        {
          exchange: '[2001:db8::1]',
          port: 25,
          priority: 0,
          using_lmtp: true,
          auth_pass: 'sekretPass',
          auth_user: 'authUser',
        },
      )
    })
  })

  const testCases = [
    { in: { exchange: '.' }, url: 'smtp://.', str: 'MX 0 smtp://.' },
    {
      in: {
        from_dns: 'example.com',
        exchange: '.',
        priority: 10,
      },
      url: 'smtp://.',
      str: 'MX 10 smtp://. (via DNS)',
    },
    {
      in: 'smtp://au:ap@192.0.2.3:25',
      url: 'smtp://au:****@192.0.2.3:25',
      str: 'MX 0 smtp://au:****@192.0.2.3:25',
    },
    {
      in: 'smtp://au:ap@192.0.2.3:465',
      url: 'smtp://au:****@192.0.2.3:465',
      str: 'MX 0 smtp://au:****@192.0.2.3:465',
    },
    {
      in: 'smtp://[2001:db8::1]:25',
      url: 'smtp://[2001:db8::1]:25',
      str: 'MX 0 smtp://[2001:db8::1]:25',
    },
    {
      in: { path: '/var/run/sock' },
      url: 'file:///var/run/sock',
      str: 'MX 0 file:///var/run/sock',
    },
  ]

  describe('toUrl', () => {
    for (const c of testCases) {
      it(`${JSON.stringify(c.in)} -> ${c.url}`, () => {
        assert.equal(new nu.HarakaMx(c.in).toUrl(), c.url)
      })
    }
  })

  describe('toString', () => {
    for (const c of testCases) {
      it(`${JSON.stringify(c.in)} -> ${c.str}`, () => {
        assert.equal(new nu.HarakaMx(c.in).toString(), c.str)
      })
    }
  })

  it('is exported from nu', () => {
    const nu2 = require('../index')
    assert.equal(typeof nu2.HarakaMx, 'function')
  })

  it('directly loadable', () => {
    const hMx = require('../lib/HarakaMx')
    assert.equal(typeof hMx, 'function')
  })
})
