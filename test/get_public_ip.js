const assert = require('node:assert')
const path = require('node:path')
const { beforeEach, describe, it } = require('node:test')

function has_stun() {
  try {
    require('@msimerson/stun')
  } catch (ignore) {
    return false
  }
  return true
}

let net_utils_mod

beforeEach(() => {
  net_utils_mod = require('../lib/get_public_ip')
  net_utils_mod.config = net_utils_mod.config.module_config(
    path.resolve('test'),
  )
})

describe('get_public_ip', () => {
  it('is accessible via main nu', () => {
    const nu = require('../index')
    assert.equal(typeof nu.get_public_ip, 'function')
    assert.equal(typeof nu.get_public_ip_async, 'function')
  })

  it('cached', () =>
    new Promise((resolve) => {
      net_utils_mod.public_ip = '1.1.1.1'
      net_utils_mod.get_public_ip((err, ip) => {
        assert.equal(null, err)
        assert.equal('1.1.1.1', ip)
        resolve()
      })
    }))

  it('normal', () =>
    new Promise((resolve) => {
      net_utils_mod.public_ip = undefined
      net_utils_mod.get_public_ip((err, ip) => {
        if (has_stun()) {
          if (err) {
            console.error(err)
          } else {
            console.log(`stun success: ${ip}`)
            assert.equal(null, err)
            assert.ok(ip, ip)
          }
        } else {
          console.log('stun skipped')
        }
        resolve()
      })
    }))

  describe('get_public_ip_async', () => {
    it('cached', async () => {
      net_utils_mod.public_ip = '1.1.1.1'
      const ip = await net_utils_mod.get_public_ip()
      assert.equal('1.1.1.1', ip)
    })

    it('normal', async () => {
      net_utils_mod.public_ip = undefined

      if (!has_stun()) {
        console.log('stun skipped')
        return
      }

      try {
        const ip = await net_utils_mod.get_public_ip()
        console.log(`stun success: ${ip}`)
        assert.ok(ip, ip)
      } catch (e) {
        console.error(e)
      }
    })
  })
})
