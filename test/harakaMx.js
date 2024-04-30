const assert = require('assert')

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

  describe('fromUri', function () {
    it('parses simple URIs', function () {
      assert.deepEqual(new this.nu.HarakaMx('smtp://192.0.2.2'), {
        exchange: '192.0.2.2',
        port: 25,
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
          port: 25,
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

  describe('toUrl', function () {
    it('has a reasonable toUrl()', function () {
      assert.equal(
        new this.nu.HarakaMx({ exchange: '.' }).toUrl(),
        'smtp://.:25',
      )

      assert.equal(
        new this.nu.HarakaMx({
          from_dns: 'example.com',
          exchange: '.',
          priority: 10,
        }).toUrl(),
        'smtp://.:25',
      )

      assert.equal(
        new this.nu.HarakaMx('smtp://au:ap@192.0.2.3:25').toUrl(),
        'smtp://au:****@192.0.2.3:25',
      )

      assert.equal(
        new this.nu.HarakaMx('smtp://au:ap@192.0.2.3:465').toUrl(),
        'smtp://au:****@192.0.2.3:465',
      )

      assert.equal(
        new this.nu.HarakaMx('smtp://[2001:db8::1]:25').toUrl(),
        'smtp://[2001:db8::1]:25',
      )
    })
  })

  describe('toString', function () {
    it('has a reasonable toString()', function () {
      assert.equal(
        new this.nu.HarakaMx({ exchange: '.' }).toString(),
        'MX 0 smtp://.:25',
      )

      assert.equal(
        new this.nu.HarakaMx({
          from_dns: 'example.com',
          exchange: '.',
          priority: 10,
        }).toString(),
        'MX 10 smtp://.:25 (from example.com)',
      )

      assert.equal(
        new this.nu.HarakaMx('smtp://au:ap@192.0.2.3:25').toString(),
        'MX 0 smtp://au:****@192.0.2.3:25',
      )

      assert.equal(
        new this.nu.HarakaMx('smtp://au:ap@192.0.2.3:465').toString(),
        'MX 0 smtp://au:****@192.0.2.3:465',
      )

      assert.equal(
        new this.nu.HarakaMx('smtp://[2001:db8::1]:25').toString(),
        'MX 0 smtp://[2001:db8::1]:25',
      )
    })
  })
})
