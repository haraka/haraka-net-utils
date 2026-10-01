'use strict'
// Socket address parser/formatter and server binding helper.
// No SMTP-specific assumptions: usable by any node:net server.

const fs = require('node:fs/promises')
const net = require('node:net')

// RFC 1123 labels, with an optional trailing dot for a fully-qualified name
const HOSTNAME_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?$/i

function invalid(addr) {
  return new Error(`Invalid socket address ${String(addr)}`)
}

// Numeric strings become numbers; anything else is kept for toString() and
// left for validatePort() to reject.
function normalizePort(value) {
  if (value === undefined || value === null || value === '') return undefined
  if (typeof value === 'number') return value
  const str = String(value)
  return /^\s*\d+\s*$/.test(str) ? Number(str) : str
}

function validatePort(port, addr) {
  if (port === undefined) return port
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new RangeError(`Invalid port ${port} in socket address ${addr}`)
  }
  return port
}

function toPort(value, addr) {
  return validatePort(normalizePort(value), addr)
}

// Zone IDs (fe80::1%eth0) name an interface, which is case-sensitive.
function normalizeIPv6(addr) {
  const pct = addr.indexOf('%')
  if (pct === -1) return addr.toLowerCase()
  return addr.slice(0, pct).toLowerCase() + addr.slice(pct)
}

function isHostname(host) {
  if (net.isIPv4(host)) return true
  // 253 octets, plus the root label's dot when given in FQDN form (RFC 1035)
  if (host.length > (host.endsWith('.') ? 254 : 253)) return false
  if (!HOSTNAME_RE.test(host)) return false
  // An all-numeric name such as 999.1.1.1 or 1.2.3 is a malformed IPv4
  // address; getaddrinfo would read 1.2.3 as 1.2.0.3 (RFC 3696 §2).
  return !/^[\d.]+$/.test(host)
}

function isValidHost(host) {
  if (typeof host !== 'string') return false
  if (host.startsWith('[') && host.endsWith(']')) return net.isIPv6(host.slice(1, -1))
  return net.isIPv6(host) || isHostname(host)
}

function parseSockaddr(addr, defaultPort = 0) {
  if (typeof addr === 'number') return { host: '::', port: validatePort(addr, addr) }
  if (typeof addr !== 'string') throw invalid(addr)
  addr = addr.trim()

  if (/^\d+$/.test(addr)) return { host: '::', port: toPort(addr, addr) }

  // A complete IPv6 address wins over a host:port split: 2001:db8::1:25 is a
  // valid address, so a port must be given as [2001:db8::1]:25 (RFC 3986).
  if (net.isIPv6(addr))
    return { host: normalizeIPv6(addr), port: toPort(defaultPort, addr) }

  let match
  if ((match = /^\[([^\]]+)\](?::(\d+))?$/.exec(addr))) {
    if (!net.isIPv6(match[1])) throw invalid(addr)
    return {
      host: normalizeIPv6(match[1]),
      port: toPort(match[2] ?? defaultPort, addr),
    }
  }

  const lastColon = addr.lastIndexOf(':')
  if (lastColon !== -1) {
    const host = addr.slice(0, lastColon)
    const port = addr.slice(lastColon + 1)
    if (/^\d+$/.test(port) && net.isIPv6(host)) {
      return { host: normalizeIPv6(host), port: toPort(port, addr) }
    }
  }

  if ((match = /^([^:]+)(?::(\d+))?$/.exec(addr)) && isHostname(match[1])) {
    return {
      host: match[1].toLowerCase(),
      port: toPort(match[2] ?? defaultPort, addr),
    }
  }

  if (addr.includes('/')) {
    match = /^(.*):([0-7]{3})$/.exec(addr)
    return match ? { path: match[1], mode: match[2] } : { path: addr }
  }

  throw invalid(addr)
}

async function removeStaleSocket(path, fsImpl) {
  let stat
  try {
    stat = await fsImpl.lstat(path)
  } catch (err) {
    if (err.code === 'ENOENT') return
    throw err
  }
  // A mistyped listen path must not delete an unrelated file.
  if (!stat.isSocket()) throw new Error(`Refusing to replace ${path}: not a socket`)
  await fsImpl.rm(path, { force: true })
}

class Endpoint {
  // Accepts parsed { host, port } or { path, mode }, server.address() output,
  // or a cluster 'listening' address (addressType -1 is a unix socket path).
  // Never throws, so it is safe for formatting log messages; use parse() to
  // validate.
  constructor(addr, defaultPort) {
    if (addr === null || typeof addr !== 'object') addr = {}
    const path = addr.path || (addr.addressType === -1 ? addr.address : undefined)
    if (path) {
      this.path = String(path)
      if (addr.mode) this.mode = String(addr.mode)
      return
    }

    let host = String(addr.address || addr.host || '::0')
    if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1)
    this.host = '::' === host ? '::0' : host
    this.port = normalizePort(addr.port ?? defaultPort)
  }

  // Throws on invalid input. Prefer this over endpoint() where the caller may
  // run in another vm context, since `instanceof Error` fails across realms.
  static parse(addr, defaultPort) {
    let ep
    if (typeof addr === 'string' || typeof addr === 'number') {
      ep = new Endpoint(parseSockaddr(addr, defaultPort))
    } else if (addr !== null && typeof addr === 'object') {
      ep = new Endpoint(addr, defaultPort)
      const host = addr.address || addr.host
      if (!ep.path && host && !isValidHost(host)) throw invalid(host)
    } else {
      throw invalid(addr)
    }
    if (!ep.path) validatePort(ep.port, ep)
    return ep
  }

  toString() {
    if (this.path) return this.mode ? `${this.path}:${this.mode}` : this.path
    const host = this.host.includes(':') ? `[${this.host}]` : this.host
    return this.port === undefined ? host : `${host}:${this.port}`
  }

  // Make server listen on this endpoint, w/optional options.
  // `fsImpl` lets tests inject a mock for node:fs/promises.
  async bind(server, opts, fsImpl = fs) {
    opts = { ...opts }

    if (this.path) {
      opts.path = this.path
      await removeStaleSocket(this.path, fsImpl)
    } else {
      // listen() treats a missing port as "any port", which is never intended
      if (this.port === undefined) throw new Error(`No port to bind for ${this}`)
      opts.host = this.host
      opts.port = validatePort(this.port, this)
    }

    // server.listen() never passes an err to the callback; failures surface
    // via the 'error' event. Race a one-shot 'error' listener against the
    // 'listening' callback so bind() rejects on EADDRINUSE/EACCES/etc.
    await new Promise((resolve, reject) => {
      const onListening = () => {
        server.off?.('error', onError)
        resolve()
      }
      const onError = (err) => {
        server.off?.('listening', onListening)
        reject(err)
      }
      server.once?.('error', onError)
      server.listen(opts, onListening)
    })

    if (!this.mode) return
    try {
      await fsImpl.chmod(this.path, parseInt(this.mode, 8))
    } catch (err) {
      // the caller sees a failed bind, so don't leave the socket listening
      server.close?.()
      throw err
    }
  }
}

// Returns an Endpoint, or an Error (NOT thrown) on parse failure — the
// historical Haraka contract. New code should use Endpoint.parse().
function endpoint(addr, defaultPort) {
  try {
    return Endpoint.parse(addr, defaultPort)
  } catch (err) {
    return err
  }
}

module.exports = { endpoint, Endpoint, parseSockaddr }
