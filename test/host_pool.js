'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')

const HostPool = require('../lib/host_pool')

// Mock socket whose connect() immediately succeeds, breaking the probe loop.
function instantConnectSocket() {
  return {
    pretendTimeout: () => {},
    setTimeout(ms, cb) {
      this.pretendTimeout = cb
    },
    listeners: {},
    on(ev, cb) {
      this.listeners[ev] = cb
    },
    connect(port, host, cb) {
      cb()
    },
    destroy() {},
  }
}

describe('HostPool', () => {
  it('returns hosts that look like ip + port', () => {
    const pool = new HostPool('1.1.1.1:1111, 2.2.2.2:2222')
    const host = pool.get_host()
    assert.ok(/\d\.\d\.\d\.\d/.test(host.host), `'${host.host}' looks like an IP`)
    assert.ok(/\d{4}/.test(host.port), `'${host.port}' looks like a port`)
  })

  it('rotates through the full list and wraps', () => {
    const pool = new HostPool('1.1.1.1:1111, 2.2.2.2:2222')
    const a = pool.get_host()
    const b = pool.get_host()
    const c = pool.get_host()
    assert.notEqual(a.host, b.host)
    assert.notEqual(c.host, b.host)
    assert.equal(c.host, a.host)
  })

  it('defaults port to 25 when omitted', () => {
    const pool = new HostPool('1.1.1.1, 2.2.2.2')
    assert.equal(pool.get_host().port, 25)
    assert.equal(pool.get_host().port, 25)
  })

  it('returns numeric ports (not strings) for consistency', () => {
    const pool = new HostPool('1.1.1.1:1111, 2.2.2.2:2222', 10, {
      shuffle: false,
    })
    for (const h of pool.hosts) {
      assert.equal(typeof h.port, 'number', `port ${h.port} should be a number`)
    }
  })

  it('treats literal "0" as missing (defaults to 25)', () => {
    const pool = new HostPool('1.1.1.1:0', 10, { shuffle: false })
    assert.equal(pool.hosts[0].port, 25)
  })

  it('skips a host marked dead', () => {
    const pool = new HostPool('1.1.1.1:1111, 2.2.2.2:2222', 0.001)
    pool.get_socket = instantConnectSocket
    pool.failed('1.1.1.1', '1111')
    for (let i = 0; i < 3; i++) {
      assert.equal(pool.get_host().host, '2.2.2.2', 'dead host is not returned')
    }
  })

  it('falls back to a dead host when every host is dead', () => {
    const pool = new HostPool('1.1.1.1:1111, 2.2.2.2:2222', 0.001)
    pool.get_socket = instantConnectSocket
    const first = pool.get_host()
    pool.failed('1.1.1.1', '1111')
    pool.failed('2.2.2.2', '2222')
    const second = pool.get_host()
    assert.ok(second, "if they're all dead, return one anyway")
    assert.notEqual(first.host, second.host, 'rotation continues')
  })

  it('probe_dead_host: retries until success, then un-deads', async () => {
    let attempt = 0
    function MockSocket() {
      this.pretendTimeout = () => {}
      this.setTimeout = (ms, cb) => {
        this.pretendTimeout = cb
      }
      this.listeners = {}
      this.on = (ev, cb) => {
        this.listeners[ev] = cb
      }
      this.emit = (ev) => this.listeners[ev]()
      this.connect = (port, host, cb) => {
        switch (++attempt) {
          case 1:
            this.pretendTimeout()
            return
          case 2:
            this.emit('error')
            return
          case 3:
            cb()
            return
          default:
            throw new Error(`unexpected probe attempt ${attempt}`)
        }
      }
      this.destroy = () => {}
    }

    const retry_secs = 0.001
    const pool = new HostPool('1.1.1.1:1111, 2.2.2.2:2222', retry_secs)
    pool.get_socket = () => new MockSocket()

    pool.failed('1.1.1.1', '1111')
    assert.ok(pool.dead_hosts['1.1.1.1:1111'])

    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        clearInterval(interval)
        reject(new Error('probe_dead_host failed'))
      }, 10_000)
      const interval = setInterval(
        () => {
          if (!pool.dead_hosts['1.1.1.1:1111']) {
            clearTimeout(timer)
            clearInterval(interval)
            resolve()
          }
        },
        retry_secs * 1000 * 3,
      )
    })
  })

  describe('logger injection', () => {
    it('is silent when no logger is provided', () => {
      const pool = new HostPool('a:1, b:2')
      assert.doesNotThrow(() => {
        // Force the all-dead fallback to exercise the warn path
        pool.dead_hosts['a:1'] = true
        pool.dead_hosts['b:2'] = true
        pool.get_host()
      })
    })

    it('routes warn() to an injected logger', () => {
      const warns = []
      const pool = new HostPool('a:1, b:2', 10, {
        logger: { warn: (m) => warns.push(m) },
      })
      pool.dead_hosts['a:1'] = true
      pool.dead_hosts['b:2'] = true
      pool.get_host()
      assert.equal(warns.length, 1)
      assert.match(warns[0], /no working hosts/)
    })
  })

  describe('probe_dead_host edge cases', () => {
    it('catches synchronous errors from get_socket() and re-throws after logging', () => {
      const warns = []
      const infos = []
      const pool = new HostPool('a:1', 10, {
        logger: {
          warn: (m) => warns.push(m),
          info: (m) => infos.push(m),
        },
      })
      pool.get_socket = () => {
        throw new Error('synthetic get_socket failure')
      }
      assert.throws(
        () =>
          pool.probe_dead_host(
            'a',
            '1',
            () => {},
            () => {},
          ),
        /synthetic get_socket failure/,
      )
      assert.equal(warns.length, 1)
      assert.match(warns[0], /ERROR in probe_dead_host/)
      assert.match(infos[0], /probing dead host/)
    })

    it('default get_socket returns a real net.Socket', () => {
      const net = require('node:net')
      const pool = new HostPool('a:1')
      const s = pool.get_socket()
      assert.ok(s instanceof net.Socket)
      s.destroy()
    })

    it('cb_if_still_dead logs and re-arms when probe times out repeatedly', async () => {
      const warns = []
      let socketCalls = 0
      const pool = new HostPool('a:1', 0.001, {
        logger: { warn: (m) => warns.push(m) },
      })
      pool.get_socket = () => {
        socketCalls += 1
        const handlers = {}
        return {
          setTimeout(_ms, cb) {
            // Fire timeout on the first two probes only; succeed on the third
            // so the cb_if_still_dead retry path runs at least once.
            if (socketCalls < 3) setImmediate(cb)
          },
          on(ev, cb) {
            handlers[ev] = cb
          },
          connect(_port, _host, cb) {
            if (socketCalls >= 3) setImmediate(cb)
          },
          destroy() {},
        }
      }
      pool.failed('a', '1')

      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('test timeout')), 5_000)
        const interval = setInterval(() => {
          if (warns.some((m) => /is still dead/.test(m))) {
            clearTimeout(timeout)
            clearInterval(interval)
            resolve()
          }
        }, 5)
      })
    })
  })

  describe('opts.shuffle = false', () => {
    it('preserves input order so tests can be deterministic', () => {
      const pool = new HostPool('a:1, b:2, c:3', 10, { shuffle: false })
      assert.deepEqual(
        pool.hosts.map((h) => h.host),
        ['a', 'b', 'c'],
      )
    })
  })
})
