'use strict'

const { describe, it } = require('node:test')
const assert = require('node:assert/strict')
const { EventEmitter } = require('node:events')

const { LineSocket, add_line_processor } = require('../lib/line_socket')

describe('add_line_processor', () => {
  it('emits one line per newline-terminated chunk', () => {
    const sock = new EventEmitter()
    const lines = []
    sock.on('line', (l) => lines.push(l))
    add_line_processor(sock)

    sock.emit('data', 'first\nsecond\n')
    assert.deepEqual(lines, ['first\n', 'second\n'])
  })

  it('buffers partial lines across chunks', () => {
    const sock = new EventEmitter()
    const lines = []
    sock.on('line', (l) => lines.push(l))
    add_line_processor(sock)

    sock.emit('data', 'partial')
    assert.deepEqual(lines, [])
    sock.emit('data', '-finish\n')
    assert.deepEqual(lines, ['partial-finish\n'])
  })

  it("flushes the unterminated tail on 'end'", () => {
    const sock = new EventEmitter()
    const lines = []
    sock.on('line', (l) => lines.push(l))
    add_line_processor(sock)

    sock.emit('data', 'no trailing newline')
    sock.emit('end')
    assert.deepEqual(lines, ['no trailing newline'])
  })

  it('emits error when buffered data exceeds max_line_length', () => {
    const sock = new EventEmitter()
    const errors = []
    sock.on('error', (e) => errors.push(e))
    sock.on('line', () => {})
    add_line_processor(sock, { max_line_length: 8 })

    sock.emit('data', 'this is way too long without a newline')
    assert.equal(errors.length, 1)
    assert.match(errors[0].message, /Line length exceeded 8 bytes/)
  })
})

describe('LineSocket', () => {
  it('is constructable and inherits from net.Socket', () => {
    const sock = new LineSocket()
    assert.equal(typeof sock.on, 'function')
    assert.equal(typeof sock.connect, 'function')
    sock.destroy()
  })

  it('emits line events when fed via the underlying socket', () => {
    const sock = new LineSocket()
    const lines = []
    sock.on('line', (l) => lines.push(l))
    // net.Socket extends Duplex; emit synthetic data to drive add_line_processor.
    sock.emit('data', 'hello\nworld\n')
    assert.deepEqual(lines, ['hello\n', 'world\n'])
    sock.destroy()
  })
})
