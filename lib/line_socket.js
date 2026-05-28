'use strict'

// net.Socket subclass that emits 'line' for each newline-terminated chunk of
// incoming data. Uses the same line-processing logic exported as
// `add_line_processor` so callers can choose: extend the class for new sockets,
// or wire the helper onto an existing socket they already have.

const net = require('node:net')

function add_line_processor(
  socket,
  { max_line_length = 4 * 1024 * 1024 } = {},
) {
  const line_regexp = /^([^\n]*\n)/
  let current_data = ''

  socket.on('data', (data) => {
    current_data += data

    if (current_data.length > max_line_length) {
      socket.emit(
        'error',
        new Error(`Line length exceeded ${max_line_length} bytes`),
      )
      current_data = ''
      return
    }

    let results
    while ((results = line_regexp.exec(current_data))) {
      const this_line = results[1]
      current_data = current_data.slice(this_line.length)
      socket.emit('line', this_line)
    }
  })

  socket.on('end', () => {
    if (current_data.length) socket.emit('line', current_data)
    current_data = ''
  })
}

class LineSocket extends net.Socket {
  constructor(options) {
    super(options)
    add_line_processor(this)
  }
}

module.exports = { LineSocket, add_line_processor }
