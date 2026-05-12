'use strict'

const net = require('node:net')
const { is_private_ip } = require('./ip')

exports.config = require('haraka-config')

exports.get_public_ip = function (cb) {
  const p = get_public_ip_impl.call(this)
  if (typeof cb !== 'function') return p
  p.then(
    (ip) => cb(null, ip),
    (err) => cb(err),
  )
}

async function get_public_ip_impl() {
  if (this.public_ip !== undefined) return this.public_ip // cache

  // manual config override, for the cases where we can't figure it out
  const smtpIni = exports.config.get('smtp.ini')?.main ?? {}
  if (smtpIni.public_ip) {
    this.public_ip = smtpIni.public_ip
    return this.public_ip
  }

  // Initialise cache value to null to prevent running
  // should we hit a timeout or the module isn't installed.
  this.public_ip = null

  try {
    this.stun = require('@msimerson/stun')
  } catch (e) {
    e.install = 'Please install stun: "npm install -g @msimerson/stun"'
    console.error(`${e.message}\n${e.install}`)
    throw e
  }

  const timeout = 10
  let timer
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('STUN timeout')), timeout * 1000)
  })

  try {
    const res = await Promise.race([
      this.stun.request(get_stun_server(), {
        maxTimeout: (timeout - 1) * 1000,
      }),
      timeoutPromise,
    ])
    const ip = res.getXorAddress().address
    if (net.isIP(ip) && !is_private_ip(ip)) {
      this.public_ip = ip
    } else {
      console.error(`STUN returned unusable IP: ${ip}`)
    }
  } catch (e) {
    // STUN unreachable (firewall, DNS, etc). Leave public_ip cached as null
    // so callers can decide what to do; never throw to them.
    console.error(`STUN lookup failed: ${e.message}`)
  } finally {
    clearTimeout(timer)
  }
  return this.public_ip
}

function get_stun_server() {
  const servers = [
    'stun.l.google.com:19302',
    'stun1.l.google.com:19302',
    'stun2.l.google.com:19302',
    'stun3.l.google.com:19302',
    'stun4.l.google.com:19302',
  ]
  return servers[Math.floor(Math.random() * servers.length)]
}
