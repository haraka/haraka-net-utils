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

    it('Unbracketed IPv6 host:port parses correctly', () => {
      assert.deepEqual({ ...endpoint('::0:25') }, { host: '::0', port: 25 })
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
    function mockFs(log, modes) {
      return {
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
        ['rm', '/foo/bar.sock', { force: true }],
        ['listen', { path: '/foo/bar.sock' }],
        ['chmod', '/foo/bar.sock', 0o764],
      ])
      assert.equal(modes['/foo/bar.sock'], 0o764)
    })

    it('rejects when chmod fails', async () => {
      const ep = endpoint('/foo/bar.sock:764')
      const failingFs = {
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
})
