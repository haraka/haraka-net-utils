const assert = require('node:assert')
const path = require('node:path')

function has_stun() {
  try {
    require('@msimerson/stun')
  } catch (e) {
    return false
  }
  return true
}

beforeEach(function (done) {
  this.net_utils = require('../lib/get_public_ip')
  this.net_utils.config = this.net_utils.config.module_config(
    path.resolve('test'),
  )
  done()
})

describe('get_public_ip', function () {

  it('is accessible via main nu', function () {
    const nu = require('../index')
    assert.equal(typeof nu.get_public_ip, 'function')
    assert.equal(typeof nu.get_public_ip_async, 'function')
  })

  it('cached', function (done) {
    this.net_utils.public_ip = '1.1.1.1'
    this.net_utils.get_public_ip((err, ip) => {
      assert.equal(null, err)
      assert.equal('1.1.1.1', ip)
      done()
    })
  })

  it('normal', function (done) {
    this.net_utils.public_ip = undefined
    this.net_utils.get_public_ip((err, ip) => {
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
      done()
    })
  })

  describe('get_public_ip_async', function () {

    it('cached', async function () {
      this.net_utils.public_ip = '1.1.1.1'
      const ip = await this.net_utils.get_public_ip()
      assert.equal('1.1.1.1', ip)
    })

    it('normal', async function () {
      this.net_utils.public_ip = undefined

      if (!has_stun()) {
        console.log('stun skipped')
        return
      }

      try {
        const ip = await this.net_utils.get_public_ip()
        console.log(`stun success: ${ip}`)
        assert.ok(ip, ip)
      } catch (e) {
        console.error(e)
      }
    })
  })
})
