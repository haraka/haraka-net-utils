'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')

const { endpoint, Endpoint, parseSockaddr } = require('../lib/endpoint')

describe('endpoint', () => {
  describe('toString()', () => {
    it('formats IPv6 default host with port', () => {
      assert.equal(endpoint(25).toString(), '[::0]:25')
    })
    it('formats IPv4 host:port', () => {
      assert.equal(endpoint('10.0.0.3', 42).toString(), '10.0.0.3:42')
    })
    it('formats unix socket path', () => {
      assert.equal(endpoint('/foo/bar.sock').toString(), '/foo/bar.sock')
    })
    it('formats unix socket path with mode', () => {
      assert.equal(endpoint('/foo/bar.sock:770').toString(), '/foo/bar.sock:770')
    })
    it('accepts server.address() return shape', () => {
      assert.equal(endpoint({ address: '::0', port: 80 }).toString(), '[::0]:80')
    })
  })

  describe('parse', () => {
    it('Number as port', () => {
      assert.deepEqual({ ...endpoint(25) }, { host: '::0', port: 25 })
    })

    it('Unbracketed IPv6 host uses default port', () => {
      assert.deepEqual({ ...endpoint('::0', 25) }, { host: '::0', port: 25 })
    })

    it('Unbracketed IPv6 that is a complete address keeps the default port', () => {
      assert.deepEqual({ ...endpoint('::0:25', 587) }, { host: '::0:25', port: 587 })
      assert.deepEqual(
        { ...endpoint('2001:db8::1:25', 587) },
        { host: '2001:db8::1:25', port: 587 },
      )
    })

    it('Unbracketed IPv6 host:port parses when the whole is not an address', () => {
      assert.deepEqual(
        { ...endpoint('2001:db8:0:0:0:0:0:1:25') },
        { host: '2001:db8:0:0:0:0:0:1', port: 25 },
      )
    })

    it('Default port if only host', () => {
      assert.deepEqual({ ...endpoint('10.0.0.3', 42) }, { host: '10.0.0.3', port: 42 })
    })

    it('Bracketed IPv6 host is normalized to lowercase', () => {
      assert.deepEqual(
        { ...endpoint('[ABCD::EF01]:2525') },
        { host: 'abcd::ef01', port: 2525 },
      )
    })

    it('Unix socket', () => {
      assert.deepEqual({ ...endpoint('/foo/bar.sock') }, { path: '/foo/bar.sock' })
    })

    it('Unix socket w/mode', () => {
      assert.deepEqual(
        { ...endpoint('/foo/bar.sock:770') },
        { path: '/foo/bar.sock', mode: '770' },
      )
    })

    it('Invalid unbracketed IPv6 host with non-numeric tail returns Error', () => {
      const ep = endpoint('::0:port')
      assert.equal(ep instanceof Error, true)
      assert.match(ep.message, /Invalid socket address/)
    })

    it('parses hostname:port form', () => {
      assert.deepEqual(
        { ...endpoint('mail.example.com:587') },
        { host: 'mail.example.com', port: 587 },
      )
    })

    it('parses bare hostname with default port', () => {
      assert.deepEqual(
        { ...endpoint('mail.example.com', 25) },
        { host: 'mail.example.com', port: 25 },
      )
    })
  })

  describe('parseSockaddr (direct)', () => {
    it('throws on completely unparseable input', () => {
      assert.throws(
        () => parseSockaddr('absolute garbage @#$%'),
        /Invalid socket address/,
      )
    })

    it('treats integer-string as port with default IPv6 host', () => {
      assert.deepEqual(parseSockaddr('80'), { host: '::', port: 80 })
    })
  })

  describe('bind()', () => {
    function mockFs(log, modes, kind = 'socket') {
      return {
        async lstat(p) {
          log.push(['lstat', p])
          if (kind === 'missing') {
            throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
          }
          return { isSocket: () => kind === 'socket' }
        },
        async rm(p, ...args) {
          log.push(['rm', p, ...args])
        },
        async chmod(p, m, ...args) {
          log.push(['chmod', p, m, ...args])
          modes[p] = m
        },
      }
    }

    function mockServer(log) {
      return {
        listen(opts, cb) {
          log.push(['listen', opts])
          if (cb) cb()
        },
      }
    }

    it('IP socket calls listen with host/port', async () => {
      const log = []
      const fakeFs = mockFs(log, {})
      const ep = endpoint('10.0.0.3:42')
      await ep.bind(mockServer(log), { backlog: 19 }, fakeFs)
      assert.deepEqual(log, [['listen', { host: '10.0.0.3', port: 42, backlog: 19 }]])
    })

    it('Unix socket removes stale path then listens', async () => {
      const log = []
      const fakeFs = mockFs(log, {})
      const ep = endpoint('/foo/bar.sock')
      await ep.bind(mockServer(log), { readableAll: true }, fakeFs)
      assert.deepEqual(log, [
        ['lstat', '/foo/bar.sock'],
        ['rm', '/foo/bar.sock', { force: true }],
        ['listen', { path: '/foo/bar.sock', readableAll: true }],
      ])
    })

    it('Unix socket w/mode chmods after listening', async () => {
      const log = []
      const modes = {}
      const fakeFs = mockFs(log, modes)
      const ep = endpoint('/foo/bar.sock:764')
      await ep.bind(mockServer(log), undefined, fakeFs)
      assert.deepEqual(log, [
        ['lstat', '/foo/bar.sock'],
        ['rm', '/foo/bar.sock', { force: true }],
        ['listen', { path: '/foo/bar.sock' }],
        ['chmod', '/foo/bar.sock', 0o764],
      ])
      assert.equal(modes['/foo/bar.sock'], 0o764)
    })

    it('rejects when chmod fails', async () => {
      const ep = endpoint('/foo/bar.sock:764')
      const failingFs = {
        async lstat() {
          return { isSocket: () => true }
        },
        async rm() {},
        async chmod() {
          throw new Error('synthetic chmod failure')
        },
      }
      await assert.rejects(
        ep.bind(mockServer([]), undefined, failingFs),
        /synthetic chmod failure/,
      )
    })
  })

  describe("bind() rejects on server 'error'", () => {
    function eventfulServer() {
      const listeners = { listening: [], error: [] }
      return {
        once(ev, cb) {
          listeners[ev].push(cb)
        },
        off(ev, cb) {
          listeners[ev] = listeners[ev].filter((l) => l !== cb)
        },
        listen() {
          // Simulate an EADDRINUSE-style failure: fire 'error' instead of calling back.
          setImmediate(() => {
            for (const l of listeners.error) l(new Error('EADDRINUSE'))
          })
        },
      }
    }

    it("propagates the server's error event to the bind() promise", async () => {
      const ep = endpoint('10.0.0.3:42')
      await assert.rejects(
        ep.bind(eventfulServer(), undefined, {
          rm: async () => {},
          chmod: async () => {},
        }),
        /EADDRINUSE/,
      )
    })
  })

  describe('Endpoint class (direct construction)', () => {
    it('accepts host + port object', () => {
      const ep = new Endpoint({ host: '1.2.3.4', port: 25 })
      assert.equal(ep.host, '1.2.3.4')
      assert.equal(ep.port, 25)
    })

    it('normalizes :: to ::0', () => {
      const ep = new Endpoint({ host: '::', port: 80 })
      assert.equal(ep.host, '::0')
    })

    it('falls back to ::0 when no host given', () => {
      const ep = new Endpoint({ port: 25 })
      assert.equal(ep.host, '::0')
    })
  })

  describe('input validation', () => {
    const rejects = (addr) => assert.ok(endpoint(addr, 25) instanceof Error, addr)

    it('accepts a fully-qualified hostname with a trailing dot', () => {
      assert.deepEqual(
        { ...endpoint('MX.Example.com.:587') },
        { host: 'mx.example.com.', port: 587 },
      )
    })

    it('rejects ports above 65535', () => {
      rejects('1.2.3.4:65536')
      rejects('[::1]:99999')
      rejects('mail.example.com:70000')
      assert.equal(endpoint('1.2.3.4:65535').port, 65535)
    })

    it('accepts an explicit port 0', () => {
      assert.equal(endpoint('1.2.3.4:0', 25).port, 0)
    })

    it('rejects malformed IPv4 and all-numeric names', () => {
      rejects('999.1.1.1')
      rejects('1.2.3')
      rejects('1.2.3.4.5')
    })

    it('rejects labels longer than 63 characters', () => {
      rejects(`${'a'.repeat(64)}.example.com`)
      assert.equal(endpoint(`${'a'.repeat(63)}.example.com`, 25).port, 25)
    })

    it('accepts bracketed scoped and IPv4-mapped IPv6', () => {
      assert.deepEqual(
        { ...endpoint('[fe80::1%en0]:25') },
        { host: 'fe80::1%en0', port: 25 },
      )
      assert.deepEqual(
        { ...endpoint('[::FFFF:1.2.3.4]:25') },
        { host: '::ffff:1.2.3.4', port: 25 },
      )
    })

    it('preserves the case of an IPv6 zone ID', () => {
      assert.equal(endpoint('FE80::1%EN0', 25).host, 'fe80::1%EN0')
      assert.equal(endpoint('[FE80::1%EN0]:25').host, 'fe80::1%EN0')
    })

    it('rejects brackets around something other than IPv6', () => {
      rejects('[1.2.3.4]:25')
      rejects('[mail.example.com]:25')
    })

    it('trims surrounding whitespace', () => {
      assert.deepEqual({ ...endpoint(' 1.2.3.4:25 ') }, { host: '1.2.3.4', port: 25 })
    })

    it('returns an Error for non-string, non-object input', () => {
      rejects(undefined)
      rejects(null)
      rejects(true)
    })
  })

  describe('construction from objects', () => {
    it('applies defaultPort when the object has no port', () => {
      assert.equal(
        endpoint({ host: 'mail.example.com' }, 25).toString(),
        'mail.example.com:25',
      )
    })

    it('leaves port undefined rather than NaN when there is none', () => {
      const ep = new Endpoint({ host: 'mail.example.com' })
      assert.equal(ep.port, undefined)
      assert.equal(ep.toString(), 'mail.example.com')
      assert.equal(new Endpoint({ host: '::1' }).toString(), '[::1]')
    })

    it('normalizes a numeric-string port', () => {
      assert.equal(new Endpoint({ host: '1.2.3.4', port: '587' }).port, 587)
    })

    it('never throws, so it is safe for log formatting', () => {
      assert.equal(
        new Endpoint({ host: '1.2.3.4', port: 'smtp' }).toString(),
        '1.2.3.4:smtp',
      )
      assert.equal(
        new Endpoint({ host: '1.2.3.4', port: 70000 }).toString(),
        '1.2.3.4:70000',
      )
    })

    it('strips brackets from an IPv6 host', () => {
      assert.equal(new Endpoint({ host: '[::1]', port: 25 }).toString(), '[::1]:25')
    })

    it('copies another Endpoint', () => {
      const ep = endpoint('/foo/bar.sock:770')
      assert.deepEqual({ ...new Endpoint(ep) }, { path: '/foo/bar.sock', mode: '770' })
    })

    it('accepts a cluster unix-socket address', () => {
      const ep = new Endpoint({ address: '/foo/bar.sock', addressType: -1, port: -1 })
      assert.equal(ep.toString(), '/foo/bar.sock')
    })
  })

  describe('Endpoint.parse()', () => {
    it('returns an Endpoint for valid input', () => {
      const ep = Endpoint.parse('[::1]:25')
      assert.ok(ep instanceof Endpoint)
      assert.equal(ep.toString(), '[::1]:25')
    })

    it('throws instead of returning an Error', () => {
      assert.throws(() => Endpoint.parse('not a host'), /Invalid socket address/)
      assert.throws(() => Endpoint.parse(undefined), /Invalid socket address/)
      assert.throws(() => Endpoint.parse('1.2.3.4:70000'), RangeError)
    })

    it('rejects an invalid port from an object or defaultPort', () => {
      assert.throws(() => Endpoint.parse({ host: '1.2.3.4', port: 'smtp' }), RangeError)
      assert.throws(() => Endpoint.parse({ host: '1.2.3.4', port: 70000 }), RangeError)
      assert.throws(() => Endpoint.parse({ host: '1.2.3.4', port: -1 }), RangeError)
      assert.throws(() => Endpoint.parse('1.2.3.4', 'smtp'), RangeError)
      assert.ok(endpoint({ host: '1.2.3.4', port: 70000 }) instanceof Error)
    })

    it('applies defaultPort to strings and objects', () => {
      assert.equal(Endpoint.parse('1.2.3.4', 587).port, 587)
      assert.equal(Endpoint.parse({ host: '1.2.3.4' }, 587).port, 587)
    })
  })

  describe('bind() safety', () => {
    const listening = () => ({
      closed: false,
      listen(opts, cb) {
        cb()
      },
      close() {
        this.closed = true
      },
    })
    const fsWith = (stat, extra = {}) => ({
      async lstat() {
        if (stat === 'missing') {
          throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
        }
        return { isSocket: () => stat === 'socket' }
      },
      async rm() {
        throw new Error('rm should not be called')
      },
      ...extra,
    })

    it('refuses to remove a path that is not a socket', async () => {
      await assert.rejects(
        endpoint('/etc/passwd').bind(listening(), undefined, fsWith('file')),
        /not a socket/,
      )
    })

    it('does not remove anything when the path is absent', async () => {
      await endpoint('/foo/new.sock').bind(listening(), undefined, fsWith('missing'))
    })

    it('closes the server when chmod fails', async () => {
      const server = listening()
      const fsImpl = fsWith('missing', {
        async chmod() {
          throw new Error('synthetic chmod failure')
        },
      })
      await assert.rejects(
        endpoint('/foo/bar.sock:770').bind(server, undefined, fsImpl),
        /synthetic chmod failure/,
      )
      assert.equal(server.closed, true)
    })

    it('refuses to bind a host without a port', async () => {
      await assert.rejects(
        new Endpoint({ host: '127.0.0.1' }).bind(listening()),
        /No port to bind/,
      )
    })
  })
})
