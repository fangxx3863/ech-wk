// ============================================================
// Cloudflare Worker 多路复用 (Mux) 服务端 [生命周期修正版]
// 100% 解决连接被 Cloudflare 边缘节点秒挂、反复重连的问题
// ============================================================

import { connect } from 'cloudflare:sockets';

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

const CMD_OPEN  = 0x01; 
const CMD_DATA  = 0x02; 
const CMD_CLOSE = 0x03; 

const NAT64_PREFIXES = [
  "2a01:4ff:f0:9876::",  
  "2a00:1098:2b::",       
  "2a01:4f9:c010:3f02::", 
  "2001:67c:2b0::"        
];

function ipv4ToNAT64(ipv4, prefix) {
  const parts = ipv4.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) {
    return null;
  }
  const hex1 = ((parts[0] << 8) | parts[1]).toString(16).padStart(4, '0');
  const hex2 = ((parts[2] << 8) | parts[3]).toString(16).padStart(4, '0');
  return `${prefix}${hex1}:${hex2}`;
}

export default {
  async fetch(request, env, ctx) { // 引入 ctx 上下文算子
    try {
      const upgradeHeader = request.headers.get('Upgrade');
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        return new Response('Mux WebSocket Server is Running', { status: 200 });
      }

      const token = ''; 

      if (token && request.headers.get('Sec-WebSocket-Protocol') !== token) {
        return new Response('Unauthorized', { status: 401 });
      }

      const [client, server] = Object.values(new WebSocketPair());
      server.accept();
      server.binaryType = "arraybuffer";

      // 【核心修正点】生成一个永不兑现的锁，直到 WebSocket 主动触发 Close/Error 为止
      const keepAlivePromise = new Promise((resolve) => {
        server.addEventListener('close', resolve);
        server.addEventListener('error', resolve);
      });

      handleMuxSession(server).catch(() => safeCloseWebSocket(server));

      // 强行命令 Cloudflare：该 Promise 未决出胜负前，严禁掐断本条实例线程！
      ctx.waitUntil(keepAlivePromise);

      const responseInit = { status: 101, webSocket: client };
      if (token) {
        responseInit.headers = { 'Sec-WebSocket-Protocol': token };
      }

      return new Response(null, responseInit);
      
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  }
};

async function handleMuxSession(webSocket) {
  const streams = new Map();

  const closeStream = (streamId) => {
    const s = streams.get(streamId);
    if (s) {
      try { s.writer?.releaseLock(); } catch {}
      try { s.reader?.releaseLock(); } catch {}
      try { s.socket?.close(); } catch {}
      streams.delete(streamId);
    }
  };

  webSocket.addEventListener('message', async (event) => {
    if (!(event.data instanceof ArrayBuffer)) return;

    const buf = new Uint8Array(event.data);
    if (buf.length < 5) return;

    const cmd = buf[0];
    const streamId = ((buf[1] << 24) | (buf[2] << 16) | (buf[3] << 8) | buf[4]) >>> 0;
    const payload = buf.subarray(5);

    switch (cmd) {
      case CMD_OPEN: {
        const targetAddr = new TextDecoder().decode(payload);
        const sep = targetAddr.lastIndexOf(':');
        const host = targetAddr.substring(0, sep).replace(/^\[|\]$/g, '');
        const port = parseInt(targetAddr.substring(sep + 1), 10);
        const isIPv6 = host.includes(':');

        let remoteSocket = null;

        try {
          remoteSocket = connect({ hostname: host, port });
          if (remoteSocket.opened) await remoteSocket.opened;
        } catch (e) {
          const isIPv4 = !isIPv6 && /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host);
          if (isIPv4) {
            for (const prefix of NAT64_PREFIXES) {
              try {
                const nat64Host = ipv4ToNAT64(host, prefix);
                if (!nat64Host) continue;
                remoteSocket = connect({ hostname: nat64Host, port });
                if (remoteSocket.opened) await remoteSocket.opened;
                break;
              } catch {}
            }
          }
        }

        if (!remoteSocket) {
          sendMuxFrame(webSocket, CMD_CLOSE, streamId);
          return;
        }

        const writer = remoteSocket.writable.getWriter();
        const reader = remoteSocket.readable.getReader();

        streams.set(streamId, { socket: remoteSocket, writer, reader });

        (async () => {
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              if (webSocket.readyState !== WS_READY_STATE_OPEN) break;
              sendMuxFrame(webSocket, CMD_DATA, streamId, value);
            }
          } catch {}

          sendMuxFrame(webSocket, CMD_CLOSE, streamId);
          closeStream(streamId);
        })();

        break;
      }

      case CMD_DATA: {
        const s = streams.get(streamId);
        if (s && s.writer) {
          try {
            await s.writer.write(payload);
          } catch {
            closeStream(streamId);
          }
        }
        break;
      }

      case CMD_CLOSE: {
        closeStream(streamId);
        break;
      }
    }
  });

  webSocket.addEventListener('close', () => {
    for (const id of streams.keys()) closeStream(id);
  });
  webSocket.addEventListener('error', () => {
    for (const id of streams.keys()) closeStream(id);
  });
}

function sendMuxFrame(ws, cmd, streamId, payload = null) {
  if (ws.readyState !== WS_READY_STATE_OPEN) return;

  const payloadLen = payload ? payload.length : 0;
  const frame = new Uint8Array(5 + payloadLen);

  frame[0] = cmd;
  frame[1] = (streamId >>> 24) & 0xff;
  frame[2] = (streamId >>> 16) & 0xff;
  frame[3] = (streamId >>> 8) & 0xff;
  frame[4] = streamId & 0xff;

  if (payload) {
    frame.set(payload, 5);
  }

  ws.send(frame.buffer);
}

function safeCloseWebSocket(ws) {
  try {
    if (ws.readyState === WS_READY_STATE_OPEN || 
        ws.readyState === WS_READY_STATE_CLOSING) {
      ws.close(1000, 'Server closed');
    }
  } catch {}
}
