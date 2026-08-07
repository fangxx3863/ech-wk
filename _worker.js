// ============================================================
// Cloudflare Worker 多路复用 (Mux) 服务端
// 100% 支持 Go 客户端多流复用 & 自动 NAT64 (IPv4 -> IPv6) 回落
// ============================================================

import { connect } from 'cloudflare:sockets';

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

// 二进制 Mux 协议命令
const CMD_OPEN  = 0x01; // 打开新流 (Payload: "host:port")
const CMD_DATA  = 0x02; // 传输数据 (Payload: 原始 TCP 数据)
const CMD_CLOSE = 0x03; // 关闭流   (Payload: 无)

// 公共 NAT64 前缀池 (用于直连 Telegram 等 IPv4 被 CF 阻断时的自动回落)
const NAT64_PREFIXES = [
  "2a01:4ff:f0:9876::",  // nat64.net (USA)
  "2a00:1098:2b::",       // nat64.net (Netherlands)
  "2a01:4f9:c010:3f02::", // nat64.net (Finland)
  "2001:67c:2b0::"        // Trex (Finland)
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
  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response('Mux WebSocket Server is Running', { status: 200 });
    }

    const token = ''; // 如需验证 token，请在此填入与 Go 客户端一致的字符串

    if (token && request.headers.get('Sec-WebSocket-Protocol') !== token) {
      return new Response('Unauthorized', { status: 401 });
    }

    const [client, server] = Object.values(new WebSocketPair());
    server.accept();
    server.binaryType = "arraybuffer";

    handleMuxSession(server).catch(() => safeCloseWebSocket(server));

    const responseInit = { status: 101, webSocket: client };
    if (token) {
      responseInit.headers = { 'Sec-WebSocket-Protocol': token };
    }

    return new Response(null, responseInit);
  }
};

async function handleMuxSession(webSocket) {
  // 维护当前 WebSocket 下的所有活跃流：streamId -> { socket, writer, reader }
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
    if (buf.length < 5) return; // 帧头至少 5 字节

    const cmd = buf[0];
    // 读取 4 字节 BigEndian uint32 的 StreamID
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

        // 1. 优先常规 Socket 直连
        try {
          remoteSocket = connect({ hostname: host, port });
          if (remoteSocket.opened) await remoteSocket.opened;
        } catch (e) {
          // 2. 直连失败（如被 CF 拦截），触发 NAT64 回落
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
          // 连不上目标，通知 Go 客户端该 Stream 建立失败
          sendMuxFrame(webSocket, CMD_CLOSE, streamId);
          return;
        }

        const writer = remoteSocket.writable.getWriter();
        const reader = remoteSocket.readable.getReader();

        streams.set(streamId, { socket: remoteSocket, writer, reader });

        // 异步循环读取远端 TCP 返回的数据，封装为 CMD_DATA 帧发送给 Go 客户端
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
    if (ws.readyState === WS_READY_STATE_OPEN || ws.readyState === WS_READY_STATE_CLOSING) {
      ws.close(1000, 'Server closed');
    }
  } catch {}
}
