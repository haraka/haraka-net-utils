'use strict'

// Round-robin host pool with dead-host probing and backoff. Generic — no
// SMTP assumptions. Logger is injected via opts; absence is fine (silent).

const net = require('node:net')

const { parseSockaddr } = require('./endpoint')

// Fisher-Yates. Inlined to avoid pulling haraka-utils as a dependency.
function shuffle(array) {
  let m = array.length
  while (m) {
    const i = Math.floor(Math.random() * m--)
    ;[array[m], array[i]] = [array[i], array[m]]
  }
  return array
}

class HostPool {
  /**
   * @param {string} hostports_str — comma/space-separated list of host:port pairs
   *   (port defaults to 25 if omitted), e.g. "1.1.1.1:22, 3.3.3.3:44"
   * @param {number} [retry_secs=10] — how long to wait before re-probing a dead host
   * @param {{ logger?: {warn?:Function, info?:Function}, shuffle?: boolean }} [opts]
   */
  constructor(hostports_str, retry_secs, opts = {}) {
    const hosts = (hostports_str || '')
      .trim()
      .split(/[\s,]+/)
      .map((hostport) => {
        try {
          const parsed = parseSockaddr(hostport, 25)
          // `|| 25` keeps the historical "treat literal :0 as missing" contract.
          return { host: parsed.host ?? '', port: parsed.port || 25 }
        } catch {
          return { host: hostport, port: 25 }
        }
      })
    this.hostports_str = hostports_str
    this.hosts = opts.shuffle === false ? hosts : shuffle(hosts)
    this.dead_hosts = {} // hostport => true
    this.last_i = 0
    this.retry_secs = retry_secs || 10
    this.logger = opts.logger
  }

  /**
   * Mark a host as failed. After retry_secs we'll re-probe it; if still down
   * we re-arm the timer, otherwise we let it back into the rotation.
   */
  failed(host, port) {
    const key = `${host}:${port}`
    const retry_msecs = this.retry_secs * 1000
    this.dead_hosts[key] = true

    const cb_if_still_dead = () => {
      this.logger?.warn?.(
        `${host} ${key} is still dead, will retry in ${this.retry_secs} secs`,
      )
      this.dead_hosts[key] = true
      setTimeout(() => {
        this.probe_dead_host(host, port, cb_if_still_dead, cb_if_alive)
      }, retry_msecs)
    }

    const cb_if_alive = () => {
      this.logger?.info?.(`${host} ${key} is back! adding back into pool`)
      delete this.dead_hosts[key]
    }

    setTimeout(() => {
      this.probe_dead_host(host, port, cb_if_still_dead, cb_if_alive)
    }, retry_msecs)
  }

  probe_dead_host(host, port, cb_if_still_dead, cb_if_alive) {
    this.logger?.info?.(`probing dead host ${host}:${port}`)

    const connect_timeout_ms = 200
    let s
    try {
      s = this.get_socket()
      s.setTimeout(connect_timeout_ms, () => {
        s.destroy()
        cb_if_still_dead()
      })
      s.on('error', () => {
        s.destroy()
        cb_if_still_dead()
      })
      s.connect(port, host, () => {
        cb_if_alive()
        s.destroy()
      })
    } catch (e) {
      this.logger?.warn?.(`ERROR in probe_dead_host, got error ${e}`)
      throw e
    }
  }

  // Overrideable for unit tests.
  get_socket() {
    return new net.Socket()
  }

  /**
   * Returns the next live host. If every host is marked dead, returns the
   * next one anyway — protects against widespread transient failures making
   * us refuse traffic to a still-functional backend.
   */
  get_host() {
    let host
    let found

    let first_i = this.last_i + 1
    if (first_i >= this.hosts.length) first_i = 0

    for (let i = 0; i < this.hosts.length; ++i) {
      let j = i + first_i
      if (j >= this.hosts.length) j -= this.hosts.length
      host = this.hosts[j]
      const key = `${host.host}:${host.port}`
      if (this.dead_hosts[key]) continue
      this.last_i = j
      found = true
      break
    }

    if (found) return host

    this.logger?.warn?.(
      `no working hosts found, retrying a dead one, config is '${this.hostports_str}'`,
    )
    this.last_i = first_i
    return this.hosts[first_i]
  }
}

module.exports = HostPool
