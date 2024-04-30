const assert = require('assert')

process.env.NODE_ENV = 'test'

describe('HarakaMx', () => {
  beforeEach(function (done) {
    this.nu = require('../index')
    done()
  })

  describe('fromObject', () => {
    it('accepts an object', function () {
      assert.deepEqual(
        new this.nu.HarakaMx({
          from_dns: 'example.com',
          exchange: '.',
          priority: 0,
        }),
        { from_dns: 'example.com', exchange: '.', priority: 0 },
      )
    })

    it('sets default priority to 0', function () {
      assert.deepEqual(new this.nu.HarakaMx({ exchange: '.' }), {
        exchange: '.',
        priority: 0,
      })
    })

    it('if optional domain provided, sets from_dns', function () {
      assert.deepEqual(new this.nu.HarakaMx({ exchange: '.' }, 'example.com'), {
        from_dns: 'example.com',
        exchange: '.',
        priority: 0,
      })
    })
  })

  describe('fromString', function () {
    it('parses a hostname', function () {
      assert.deepEqual(new this.nu.HarakaMx('mail.example.com'), {
        exchange: 'mail.example.com',
        priority: 0,
      })
    })

    it('parses a hostname:port', function () {
      assert.deepEqual(new this.nu.HarakaMx('mail.example.com:25'), {
        exchange: 'mail.example.com',
        port: 25,
        priority: 0,
      })
    })

    it('parses an IPv4', function () {
      assert.deepEqual(new this.nu.HarakaMx('192.0.2.1'), {
        exchange: '192.0.2.1',
        priority: 0,
      })
    })

    it('parses an IPv4:port', function () {
      assert.deepEqual(new this.nu.HarakaMx('192.0.2.1:25'), {
        exchange: '192.0.2.1',
        port: 25,
        priority: 0,
      })
    })

    it('parses an IPv6', function () {
      assert.deepEqual(new this.nu.HarakaMx('2001:db8::1'), {
        exchange: '2001:db8::1',
        priority: 0,
      })
    })

    it('parses an IPv6:port', function () {
      assert.deepEqual(new this.nu.HarakaMx('2001:db8::1:25'), {
        exchange: '2001:db8::1',
        port: 25,
        priority: 0,
      })
    })

    it('parses an [IPv6]:port', function () {
      assert.deepEqual(new this.nu.HarakaMx('[2001:db8::1]:25'), {
        exchange: '2001:db8::1',
        port: 25,
        priority: 0,
      })
    })
  })

  describe('fromUrl', function () {
    it('parses simple URIs', function () {
      assert.deepEqual(new this.nu.HarakaMx('smtp://192.0.2.2'), {
        exchange: '192.0.2.2',
        priority: 0,
      })

      assert.deepEqual(new this.nu.HarakaMx('smtp://[2001:db8::1]:25'), {
        exchange: '[2001:db8::1]',
        port: 25,
        priority: 0,
      })
    })

    it('parses more complex URIs', function () {
      assert.deepEqual(
        new this.nu.HarakaMx('smtp://authUser:sekretPass@[2001:db8::1]'),
        {
          exchange: '[2001:db8::1]',
          priority: 0,
          auth_pass: 'sekretPass',
          auth_user: 'authUser',
        },
      )

      assert.deepEqual(
        new this.nu.HarakaMx('lmtp://authUser:sekretPass@[2001:db8::1]:25'),
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

  describe('toUrl', function () {
    for (const c of testCases) {
      it(`${JSON.stringify(c.in)} -> ${c.url}`, function () {
        assert.equal(new this.nu.HarakaMx(c.in).toUrl(), c.url)
      })
    }
  })

  describe('toString', function () {
    for (const c of testCases) {
      it(`${JSON.stringify(c.in)} -> ${c.str}`, function () {
        assert.equal(new this.nu.HarakaMx(c.in).toString(), c.str)
      })
    }
  })

  it('is exported from nu', function () {
    const nu = require('../index')
    assert.equal(typeof nu.HarakaMx, 'function')
  })

  it('directly loadable', function () {
    const hMx = require('../lib/HarakaMx')
    assert.equal(typeof hMx, 'function')
  })
})
