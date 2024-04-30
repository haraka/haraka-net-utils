'use strict'

const { Resolver } = require('node:dns').promises
const dns = new Resolver({ timeout: 25000, tries: 1 })
const net = require('node:net')

const punycode = require('punycode.js')

const HarakaMx = require('./HarakaMx')

function normalizeDomain(raw_domain) {
  let domain = raw_domain

  if (/@/.test(domain)) {
    domain = domain.split('@').pop()
    // console.log(`\treduced ${raw_domain} to ${domain}.`)
  }

  if (/^xn--/.test(domain)) {
    // is punycode IDN with ACE, ASCII Compatible Encoding
  } else if (domain !== punycode.toASCII(domain)) {
    domain = punycode.toASCII(domain)
    console.log(`\tACE encoded '${raw_domain}' to '${domain}'`)
  }

  return domain
}

function fatal_mx_err(err) {
  // Possible DNS errors
  // NODATA
  // FORMERR
  // BADRESP
  // NOTFOUND
  // BADNAME
  // TIMEOUT
  // CONNREFUSED
  // NOMEM
  // DESTRUCTION
  // NOTIMP
  // EREFUSED
  // SERVFAIL

  switch (err.code) {
    case 'ENODATA':
    case 'ENOTFOUND':
      // likely a hostname with no MX record, drop through
      return false
    default:
      return err
  }
}

exports.get_mx = async (raw_domain, cb) => {
  const domain = normalizeDomain(raw_domain)

  try {
    let exchanges = await dns.resolveMx(domain)
    if (exchanges && exchanges.length) {
      exchanges = exchanges.map((e) => new HarakaMx(e, domain))
      if (cb) return cb(null, exchanges)
      return exchanges
    }
    // no MX record(s), fall through
  } catch (err) {
    if (fatal_mx_err(err)) {
      if (cb) return cb(err, [])
      throw err
    }
    // non-terminal DNS failure, fall through
  }

  const exchanges = await this.get_implicit_mx(domain)
  if (cb) return cb(null, exchanges)
  return exchanges
}

exports.get_implicit_mx = async (domain) => {
  // console.log(`No MX for ${domain}, trying AAAA & A records`)

  const r = await Promise.allSettled([
    dns.resolve6(domain),
    dns.resolve4(domain),
  ])

  return r
    .filter((a) => a.status === 'fulfilled')
    .flatMap((a) => a.value.map((ip) => new HarakaMx(ip, domain)))
}

exports.resolve_mx_hosts = async (mxes) => {
  // for the given list of MX exchanges, resolve the hostnames to IPs
  const promises = []

  for (const mx of mxes) {
    if (!mx.exchange) {
      // console.error(`MX without an exchange. could be a socket`)
      promises.push(mx)
      continue
    }

    if (net.isIP(mx.exchange)) {
      promises.push(mx) // already resolved
      continue
    }

    // resolve AAAA and A since mx.exchange is a hostname
    promises.push(
      dns
        .resolve6(mx.exchange)
        .then((ips) =>
          ips.map((ip) => ({ ...mx, exchange: ip, from_dns: mx.exchange })),
        ),
    )

    promises.push(
      dns
        .resolve4(mx.exchange)
        .then((ips) =>
          ips.map((ip) => ({ ...mx, exchange: ip, from_dns: mx.exchange })),
        ),
    )
  }

  const settled = await Promise.allSettled(promises)

  return settled.filter((s) => s.status === 'fulfilled').flatMap((s) => s.value)
}
