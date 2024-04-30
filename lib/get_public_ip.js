'use strict'

exports.config = require('haraka-config')

exports.get_public_ip_async = async function () {
  if (this.public_ip !== undefined) return this.public_ip // cache

  // manual config override, for the cases where we can't figure it out
  const smtpIni = exports.config.get('smtp.ini').main
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
    e.install = 'Please install stun: "npm install -g stun"'
    console.error(`${e.msg}\n${e.install}`)
    return
  }

  const timeout = 10
  const timer = setTimeout(() => {
    return new Error('STUN timeout')
  }, timeout * 1000)

  // Connect to STUN Server
  const res = await this.stun.request(get_stun_server(), {
    maxTimeout: (timeout - 1) * 1000,
  })
  this.public_ip = res.getXorAddress().address
  clearTimeout(timer)
  return this.public_ip
}

exports.get_public_ip = async function (cb) {
  if (!cb) return exports.get_public_ip_async()

  if (this.public_ip !== undefined) return cb(null, this.public_ip) // cache

  // manual config override, for the cases where we can't figure it out
  const smtpIni = exports.config.get('smtp.ini').main
  if (smtpIni.public_ip) {
    this.public_ip = smtpIni.public_ip
    return cb(null, this.public_ip)
  }

  // Initialise cache value to null to prevent running
  // should we hit a timeout or the module isn't installed.
  this.public_ip = null

  try {
    this.stun = require('@msimerson/stun')
  } catch (e) {
    e.install = 'Please install stun: "npm install -g stun"'
    console.error(`${e.msg}\n${e.install}`)
    return cb(e)
  }

  const timeout = 10
  const timer = setTimeout(() => {
    return cb(new Error('STUN timeout'))
  }, timeout * 1000)

  // Connect to STUN Server
  this.stun.request(
    get_stun_server(),
    { maxTimeout: (timeout - 1) * 1000 },
    (error, res) => {
      if (timer) clearTimeout(timer)
      if (error) return cb(error)

      this.public_ip = res.getXorAddress().address
      cb(null, this.public_ip)
    },
  )
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
