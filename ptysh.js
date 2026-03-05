const http = require('http')
const WebSocket = require('ws')
const pty = require('node-pty')

function parseArgs() {
  const args = process.argv.slice(2)
  const config = {
    port: 8877,
    command: 'bash',
    args: [],
    cols: 100,
    rows: 44
  }

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' || args[i] === '-p') {
      config.port = parseInt(args[++i], 10)
    } else if (args[i] === '--command' || args[i] === '-c') {
      config.command = args[++i]
    } else if (args[i] === '--cols') {
      config.cols = parseInt(args[++i], 10)
    } else if (args[i] === '--rows') {
      config.rows = parseInt(args[++i], 10)
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log('Usage: node index.js [options]')
      console.log('')
      console.log('Options:')
      console.log('  -p, --port <port>      Port to listen on (default: 8877)')
      console.log('  -c, --command <cmd>    Command to run (default: bash)')
      console.log('  --cols <cols>          Terminal columns (default: 80)')
      console.log('  --rows <rows>          Terminal rows (default: 24)')
      console.log('  -h, --help             Show this help')
      console.log('')
      console.log('Example:')
      console.log('  node index.js --port 9000 --command /bin/sh')
      console.log('')
      console.log('Equivalent to: socat STDIO EXEC:"command",setsid,ctty,openpty,stderr')
      process.exit(0)
    }
  }

  return config
}

const config = parseArgs()

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' })
  res.end('WebSocket server ready\n')
})

const wss = new WebSocket.Server({ noServer: true })

server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request)
  })
})

wss.on('connection', (ws, request) => {
  console.log('WebSocket connection from', request.socket.remoteAddress)

  const ptyProc = pty.spawn(config.command, [], {
    name: 'xterm-256color',
    cols: config.cols,
    rows: config.rows,
    cwd: process.env.HOME || process.cwd(),
    env: process.env
  })

  ws.on('message', (data) => {
    ptyProc.write(data.toString())
  })

  ptyProc.onData((data) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data)
    }
  })

  ptyProc.onExit(({ exitCode }) => {
    console.log('PTY exited with code', exitCode)
    if (ws.readyState === WebSocket.OPEN) {
      ws.close()
    }
  })

  ws.on('close', () => {
    console.log('WebSocket closed')
    ptyProc.kill()
  })

  ws.on('error', (err) => {
    console.error('WebSocket error:', err.message)
    ptyProc.kill()
  })
})

server.listen(config.port, () => {
  console.log(`WebSocket server listening on port ${config.port}, running command: ${config.command}`)
  console.log(`Terminal size: ${config.cols}x${config.rows}`)
  console.log('PTY mode enabled (equivalent to socat with setsid,ctty,openpty,stderr)')
})
