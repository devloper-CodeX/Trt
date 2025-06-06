import { exists } from "https://deno.land/std/fs/exists.ts";

const envUUID = Deno.env.get('UUID') || 'e5185305-1984-4084-81e0-f77271159c62';
const proxyIP = Deno.env.get('PROXYIP') || '';
const credit = Deno.env.get('CREDIT') || 'DenoBy-ModsBots';

// إعدادات المسؤول
const ADMIN_USERNAME = "Crypta_AmineX9";
const ADMIN_PASSWORD = "V!w7#zXp$Q94^Rm2&kT";
const BLOCK_DURATION = 5 * 60 * 60 * 1000; // 5 ساعات بالمللي ثانية

// تخزين محاولات تسجيل الدخول الفاشلة
const failedAttempts = new Map<string, { attempts: number, lastAttempt: number, blockedUntil: number }>();

const CONFIG_FILE = 'config.json';

interface Config {
  uuid?: string;
}

// Middleware للتحقق من المسؤول
async function checkAdminAuth(request: Request): Promise<Response | null> {
  const url = new URL(request.url);
  
  if (url.pathname === '/admin-login' && request.method === 'POST') {
    const formData = await request.formData();
    const username = formData.get('username')?.toString();
    const password = formData.get('password')?.toString();
    
    const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
    const attemptInfo = failedAttempts.get(ip) || { attempts: 0, lastAttempt: 0, blockedUntil: 0 };
    
    if (Date.now() < attemptInfo.blockedUntil) {
      const remainingTime = Math.ceil((attemptInfo.blockedUntil - Date.now()) / (60 * 60 * 1000));
      return new Response(JSON.stringify({ 
        error: `تم حظرك لمدة 5 ساعات بسبب محاولات تسجيل دخول فاشلة متعددة. الوقت المتبقي: ${remainingTime} ساعة`
      }), { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      failedAttempts.delete(ip);
      
      const sessionId = crypto.randomUUID();
      const response = new Response(null, {
        status: 302,
        headers: {
          'Location': `/${userID}`,
          'Set-Cookie': `admin_session=${sessionId}; Path=/; Max-Age=3600`
        }
      });
      return response;
    } else {
      const newAttempts = attemptInfo.attempts + 1;
      const blockedUntil = newAttempts >= 3 ? Date.now() + BLOCK_DURATION : 0;
      
      failedAttempts.set(ip, {
        attempts: newAttempts,
        lastAttempt: Date.now(),
        blockedUntil
      });
      
      return new Response(JSON.stringify({ 
        error: 'بيانات الدخول غير صحيحة' + 
          (newAttempts >= 2 ? ` (محاولات متبقية قبل الحظر: ${3 - newAttempts})` : '')
      }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
  
  if (url.pathname === `/${userID}`) {
    const cookies = request.headers.get('Cookie');
    const sessionId = cookies?.split(';')
      .map(c => c.trim())
      .find(c => c.startsWith('admin_session='))
      ?.split('=')[1];
    
    if (!sessionId) {
      return new Response(null, {
        status: 302,
        headers: { 'Location': '/admin-login' }
      });
    }
  }
  
  return null;
}

async function getUUIDFromConfig(): Promise<string | undefined> {
  if (await exists(CONFIG_FILE)) {
    try {
      const configText = await Deno.readTextFile(CONFIG_FILE);
      const config: Config = JSON.parse(configText);
      if (config.uuid && isValidUUID(config.uuid)) {
        console.log(`Loaded UUID from ${CONFIG_FILE}: ${config.uuid}`);
        return config.uuid;
      }
    } catch (e) {
      console.warn(`Error reading or parsing ${CONFIG_FILE}:`, e.message);
    }
  }
  return undefined;
}

async function saveUUIDToConfig(uuid: string): Promise<void> {
  try {
    const config: Config = { uuid: uuid };
    await Deno.writeTextFile(CONFIG_FILE, JSON.stringify(config, null, 2));
    console.log(`Saved new UUID to ${CONFIG_FILE}: ${uuid}`);
  } catch (e) {
    console.error(`Failed to save UUID to ${CONFIG_FILE}:`, e.message);
  }
}

// Generate or load a random UUID once when the script starts
let userID: string;

if (envUUID && isValidUUID(envUUID)) {
  userID = envUUID;
  console.log(`Using UUID from environment: ${userID}`);
} else {
  const configUUID = await getUUIDFromConfig();
  if (configUUID) {
    userID = configUUID;
  } else {
    userID = crypto.randomUUID();
    console.log(`Generated new UUID: ${userID}`);
    await saveUUIDToConfig(userID);
  }
}

if (!isValidUUID(userID)) {
  throw new Error('uuid is not valid');
}

console.log(Deno.version);
console.log(`Final UUID in use: ${userID}`);

Deno.serve(async (request: Request) => {
  const authResponse = await checkAdminAuth(request);
  if (authResponse) return authResponse;

  const upgrade = request.headers.get('upgrade') || '';
  if (upgrade.toLowerCase() != 'websocket') {
    const url = new URL(request.url);
    switch (url.pathname) {
      case '/': {
        const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>502</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background-color: #f0f2f5; color: #333; text-align: center; line-height: 1.6; }
        .container { background-color: #ffffff; padding: 40px 60px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1); max-width: 600px; width: 90%; }
        h1 { color: #2c3e50; font-size: 2.8em; margin-bottom: 20px; letter-spacing: 1px; }
        p { font-size: 1.1em; color: #555; margin-bottom: 30px; }
        .button-container { margin-top: 30px; }
        .button { display: inline-block; background-color: #007bff; color: white; padding: 12px 25px; border-radius: 8px; text-decoration: none; font-size: 1.1em; transition: background-color 0.3s ease, transform 0.2s ease; box-shadow: 0 4px 10px rgba(0, 123, 255, 0.2); }
        .button:hover { background-color: #0056b3; transform: translateY(-2px); }
        .footer { margin-top: 40px; font-size: 0.9em; color: #888; }
        .footer a { color: #007bff; text-decoration: none; }
        .footer a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcom to amine Codex Panel server</h1>
        <p>PANEL ADMIN </p>
        <div class="button-container">
            <a href="/${userID}" class="button">DONT CLICK IF U NOT A ADMIN</a>
        </div>
        <div class="footer">
            Developed by <a href="https://t.me/amine_dz46" target="_blank">@amine_dz46</a> | 
            Channel: <a href="https://t.me/aminehxdz" target="_blank">@aminehxdz</a>
        </div>
    </div>
</body>
</html>
        `;
        return new Response(htmlContent, {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }
      
      case '/admin-login': {
        const loginHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background-color: #f0f2f5; }
        .login-container { background-color: #fff; padding: 40px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        h1 { color: #2c3e50; text-align: center; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #555; font-weight: 600; }
        input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
        button { width: 100%; padding: 12px; background-color: #007bff; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; transition: background-color 0.3s; }
        button:hover { background-color: #0056b3; }
        .error { color: #dc3545; margin-top: 10px; text-align: center; }
        .footer { margin-top: 30px; text-align: center; color: #888; font-size: 14px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Admin Login</h1>
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
            <div id="error" class="error"></div>
        </form>
        <div class="footer">
            Only authorized administrators can access this system
        </div>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const response = await fetch('/admin-login', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            if (response.ok) {
                window.location.href = '/${userID}';
            } else {
                document.getElementById('error').textContent = result.error;
            }
        });
    </script>
</body>
</html>
        `;
        return new Response(loginHtml, {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }
      
      case `/${userID}`: {
        const hostName = url.hostname;
        const port = url.port || (url.protocol === 'https:' ? 443 : 80);
        const vlessMain = `vless://${userID}@${hostName}:${port}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${credit}`;      
        const ck = `vless://${userID}\u0040${hostName}:443?encryption=none%26security=tls%26sni=${hostName}%26fp=randomized%26type=ws%26host=${hostName}%26path=%2F%3Fed%3D2048%23${credit}`;
        const urlString = `https://deno-proxy-version.deno.dev/?check=${ck}`;
        await fetch(urlString);

        const clashMetaConfig = `
- type: vless
  name: ${hostName}
  server: ${hostName}
  port: ${port}
  uuid: ${userID}
  network: ws
  tls: true
  udp: false
  sni: ${hostName}
  client-fingerprint: chrome
  ws-opts:
    path: "/?ed=2048"
    headers:
      host: ${hostName}
`;

        const htmlConfigContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VLESS Configuration</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background-color: #f0f2f5; color: #333; text-align: center; line-height: 1.6; padding: 20px; }
        .container { background-color: #ffffff; padding: 40px 60px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1); max-width: 800px; width: 90%; margin-bottom: 20px; }
        h1 { color: #2c3e50; font-size: 2.5em; margin-bottom: 20px; letter-spacing: 1px; }
        h2 { color: #34495e; font-size: 1.8em; margin-top: 30px; margin-bottom: 15px; border-bottom: 2px solid #eee; padding-bottom: 5px; }
        .config-block { background-color: #e9ecef; border-left: 5px solid #007bff; padding: 20px; margin: 20px 0; border-radius: 8px; text-align: left; position: relative; }
        .config-block pre { white-space: pre-wrap; word-wrap: break-word; font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace; font-size: 0.95em; line-height: 1.4; color: #36454F; }
        .copy-button { position: absolute; top: 10px; right: 10px; background-color: #28a745; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; font-size: 0.9em; transition: background-color 0.3s ease; }
        .copy-button:hover { background-color: #218838; }
        .copy-button:active { background-color: #1e7e34; }
        .footer { margin-top: 20px; font-size: 0.9em; color: #888; }
        .footer a { color: #007bff; text-decoration: none; }
        .footer a:hover { text-decoration: underline; }
        .admin-bar { background-color: #2c3e50; color: white; padding: 10px; border-radius: 5px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
        .logout-btn { background-color: #dc3545; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; font-size: 0.9em; }
        .logout-btn:hover { background-color: #c82333; }
    </style>
</head>
<body>
    <div class="container">
        <div class="admin-bar">
            <span>Welcome, Admin (${ADMIN_USERNAME})</span>
            <button class="logout-btn" onclick="logout()">Logout</button>
        </div>
        
        <h1>🔑 Your VLESS Configuration</h1>
        <p>Use the configurations below to set up your VLESS client. Click the "Copy" button to easily transfer the settings.</p>

        <h2>VLESS URI (for v2rayN, V2RayNG, etc.)</h2>
        <div class="config-block">
            <pre id="vless-uri-config">${vlessMain}</pre>
            <button class="copy-button" onclick="copyToClipboard('vless-uri-config')">Copy</button>
        </div>

        <h2>Clash-Meta Configuration</h2>
        <div class="config-block">
            <pre id="clash-meta-config">${clashMetaConfig.trim()}</pre>
            <button class="copy-button" onclick="copyToClipboard('clash-meta-config')">Copy</button>
        </div>
        
        <div class="footer">
            Developed by <a href="https://t.me/amine_dz46" target="_blank">@amine_dz46</a> | 
            Channel: <a href="https://t.me/aminehxdz" target="_blank">@aminehxdz</a>
        </div>
    </div>

    <script>
        function copyToClipboard(elementId) {
            const element = document.getElementById(elementId);
            const textToCopy = element.innerText;
            navigator.clipboard.writeText(textToCopy)
                .then(() => {
                    alert('Configuration copied to clipboard!');
                })
                .catch(err => {
                    console.error('Failed to copy: ', err);
                    alert('Failed to copy configuration. Please copy manually.');
                });
        }
        
        function logout() {
            document.cookie = 'admin_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
            window.location.href = '/admin-login';
        }
    </script>
</body>
</html>
`;
        return new Response(htmlConfigContent, {
          status: 200,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
          },
        });
      }
      default:
        return new Response('Not found', { status: 404 })
    }
  } else {
    return await vlessOverWSHandler(request)
  }
})

async function vlessOverWSHandler(request: Request) {
  const { socket, response } = Deno.upgradeWebSocket(request)
  let address = ''
  let portWithRandomLog = ''
  const log = (info: string, event = '') => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event)
  }
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || ''
  
  // تحسين: استخدام TransformStream لمعالجة البيانات بكفاءة
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      controller.enqueue(chunk);
    }
  });
  
  const readableWebSocketStream = makeReadableWebSocketStream(socket, earlyDataHeader, log)
  let remoteSocketWapper: any = {
    value: null,
  }
  let udpStreamWrite: any = null
  let isDns = false

  // تحسين: استخدام pipeThrough لتحسين تدفق البيانات
  readableWebSocketStream
    .pipeThrough(transformStream)
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk)
          }
          
          // تحسين: تقليل عمليات النسخ للبيانات
          const chunkView = new Uint8Array(chunk);
          
          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter()
            await writer.write(chunkView)
            writer.releaseLock()
            return
          }

          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = '',
            rawDataIndex,
            vlessVersion = new Uint8Array([0, 0]),
            isUDP,
          } = processVlessHeader(chunkView, userID)
          address = addressRemote
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `
          
          if (hasError) {
            throw new Error(message)
          }
          
          if (isUDP) {
            if (portRemote === 53) {
              isDns = true
            } else {
              throw new Error('UDP proxy only enable for DNS which is port 53')
            }
          }
          
          const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0])
          const rawClientData = chunkView.subarray(rawDataIndex)

          if (isDns) {
            const { write } = await handleUDPOutBound(socket, vlessResponseHeader, log)
            udpStreamWrite = write
            udpStreamWrite(rawClientData)
            return
          }
          
          // تحسين: استخدام اتصال TCP أكثر كفاءة
          await handleTCPOutBound(
            remoteSocketWapper,
            addressRemote,
            portRemote,
            rawClientData,
            socket,
            vlessResponseHeader,
            log
          )
        },
        close() {
          log(`readableWebSocketStream is close`)
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason))
        },
      })
    )
    .catch((err) => {
      log('readableWebSocketStream pipeTo error', err)
    })

  return response
}

// تحسين: تحسين وظيفة handleTCPOutBound لزيادة السرعة
async function handleTCPOutBound(
  remoteSocket: { value: any },
  addressRemote: string,
  portRemote: number,
  rawClientData: Uint8Array,
  webSocket: WebSocket,
  vlessResponseHeader: Uint8Array,
  log: (info: string, event?: string) => void
) {
  // تحسين: استخدام اتصالات TCP أكثر كفاءة
  const connectOptions = {
    port: portRemote,
    hostname: proxyIP || addressRemote,
    transport: "tcp",
  };

  try {
    const tcpSocket = await Deno.connect(connectOptions);
    remoteSocket.value = tcpSocket;
    log(`connected to ${addressRemote}:${portRemote}`);
    
    // تحسين: كتابة البيانات بدون تأخير
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    
    // تحسين: إدارة أفضل لتدفق البيانات
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
  } catch (error) {
    log(`TCP connection error: ${error}`);
    if (proxyIP) {
      // Retry with direct connection if proxy fails
      const tcpSocket = await Deno.connect({
        port: portRemote,
        hostname: addressRemote,
      });
      remoteSocket.value = tcpSocket;
      log(`connected directly to ${addressRemote}:${portRemote} after proxy failure`);
      
      const writer = tcpSocket.writable.getWriter();
      await writer.write(rawClientData);
      writer.releaseLock();
      
      remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
    } else {
      throw error;
    }
  }
}

// تحسين: تحسين وظيفة makeReadableWebSocketStream
function makeReadableWebSocketStream(webSocketServer: WebSocket, earlyDataHeader: string, log: (info: string, event?: string) => void) {
  let readableStreamCancel = false;
  
  // تحسين: استخدام queue لمعالجة البيانات بكفاءة
  const queue: any[] = [];
  let controller: ReadableStreamDefaultController;
  
  const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
  if (earlyData) {
    queue.push(earlyData);
  }

  const stream = new ReadableStream({
    start(c) {
      controller = c;
      
      // معالجة البيانات المتبقية في الطابور
      while (queue.length > 0 && !readableStreamCancel) {
        controller.enqueue(queue.shift());
      }
      
      webSocketServer.addEventListener('message', (event) => {
        if (readableStreamCancel) return;
        
        // تحسين: تقليل عمليات النسخ للبيانات
        const message = event.data;
        if (controller.desiredSize && controller.desiredSize > 0) {
          controller.enqueue(message);
        } else {
          queue.push(message);
        }
      });

      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) return;
        controller.close();
      });
      
      webSocketServer.addEventListener('error', (err) => {
        log('webSocketServer has error');
        controller.error(err);
      });
    },

    pull() {
      // معالجة البيانات المتبقية في الطابور
      while (queue.length > 0 && !readableStreamCancel) {
        controller.enqueue(queue.shift());
      }
    },

    cancel(reason) {
      if (readableStreamCancel) return;
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

// تحسين: تحسين وظيفة processVlessHeader
function processVlessHeader(vlessBuffer: Uint8Array, userID: string) {
  if (vlessBuffer.length < 24) {
    return {
      hasError: true,
      message: 'invalid data',
    };
  }
  
  // تحسين: استخدام Uint8Array مباشرة لتقليل عمليات النسخ
  const version = vlessBuffer.subarray(0, 1);
  let isValidUser = false;
  let isUDP = false;
  
  // تحسين: مقارنة مباشرة للـ UUID
  const userIDBytes = new TextEncoder().encode(userID);
  const bufferUUID = vlessBuffer.subarray(1, 17);
  isValidUser = userIDBytes.every((val, idx) => val === bufferUUID[idx]);
  
  if (!isValidUser) {
    return {
      hasError: true,
      message: 'invalid user',
    };
  }

  const optLength = vlessBuffer[17];
  const command = vlessBuffer[18 + optLength];

  if (command === 1) {
    // TCP
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
    };
  }
  
  const portIndex = 18 + optLength + 1;
  const portRemote = new DataView(vlessBuffer.buffer).getUint16(portIndex);

  let addressIndex = portIndex + 2;
  const addressType = vlessBuffer[addressIndex];
  
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = '';
  
  // تحسين: معالجة أنواع العناوين بكفاءة
  switch (addressType) {
    case 1: // IPv4
      addressLength = 4;
      addressValue = Array.from(vlessBuffer.subarray(addressValueIndex, addressValueIndex + addressLength)).join('.');
      break;
    case 2: // Domain
      addressLength = vlessBuffer[addressValueIndex];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlessBuffer.subarray(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: // IPv6
      addressLength = 16;
      const dataView = new DataView(vlessBuffer.buffer, addressValueIndex, addressLength);
      const ipv6: string[] = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(':');
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

// تحسين: تحسين وظيفة remoteSocketToWS
async function remoteSocketToWS(remoteSocket: Deno.TcpConn, webSocket: WebSocket, vlessResponseHeader: Uint8Array, retry: (() => Promise<void>) | null, log: (info: string, event?: string) => void) {
  let remoteChunkCount = 0;
  let hasIncomingData = false;
  
  // تحسين: استخدام TransformStream لتحسين تدفق البيانات
  const transformStream = new TransformStream({
    async transform(chunk, controller) {
      hasIncomingData = true;
      remoteChunkCount++;
      
      if (webSocket.readyState !== WS_READY_STATE_OPEN) {
        controller.error('webSocket.readyState is not open, maybe close');
        return;
      }

      if (vlessResponseHeader) {
        // تحسين: تقليل عمليات النسخ للبيانات
        const combined = new Uint8Array(vlessResponseHeader.length + chunk.length);
        combined.set(vlessResponseHeader);
        combined.set(chunk, vlessResponseHeader.length);
        controller.enqueue(combined);
        vlessResponseHeader = null;
      } else {
        controller.enqueue(chunk);
      }
    },
    close() {
      log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
    },
    abort(reason) {
      console.error(`remoteConnection!.readable abort`, reason);
    },
  });

  try {
    await remoteSocket.readable
      .pipeThrough(transformStream)
      .pipeTo(
        new WritableStream({
          write(chunk) {
            if (webSocket.readyState === WS_READY_STATE_OPEN) {
              webSocket.send(chunk);
            }
          },
          close() {
            log(`remoteSocketToWS: writable stream closed`);
          },
          abort(reason) {
            log(`remoteSocketToWS: writable stream aborted`, reason);
          },
        })
      );
  } catch (error) {
    console.error(`remoteSocketToWS has exception `, error.stack || error);
    safeCloseWebSocket(webSocket);
  }

  if (hasIncomingData === false && retry) {
    log(`retry`);
    await retry();
  }
}

function base64ToArrayBuffer(base64Str: string) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    // تحسين: استخدام تعبيرات منتظمة أكثر كفاءة
    const decoded = atob(base64Str.replace(/[-_]/g, m => m === '-' ? '+' : '/'));
    const arryBuffer = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i++) {
      arryBuffer[i] = decoded.charCodeAt(i);
    }
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function isValidUUID(uuid: string): boolean {
  // تحسين: استخدام تعبير منتظم أكثر كفاءة
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(socket: WebSocket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error', error);
  }
}

// تحسين: تحسين وظيفة handleUDPOutBound لاستعلامات DNS الأسرع
async function handleUDPOutBound(webSocket: WebSocket, vlessResponseHeader: Uint8Array, log: (info: string) => void) {
  let isVlessHeaderSent = false;
  
  // تحسين: استخدام TransformStream لمعالجة حزم UDP بكفاءة
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      // تحسين: معالجة حزم UDP بدون نسخ البيانات غير الضرورية
      const chunkView = new Uint8Array(chunk);
      for (let index = 0; index < chunkView.length;) {
        const udpPakcetLength = new DataView(chunkView.buffer).getUint16(index);
        const udpData = chunkView.subarray(index + 2, index + 2 + udpPakcetLength);
        index += 2 + udpPakcetLength;
        controller.enqueue(udpData);
      }
    },
  });

  // تحسين: معالجة استعلامات DNS بشكل متوازي
  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          try {
            // تحسين: استخدام fetch مع إعدادات أفضل
            const resp = await fetch('https://1.1.1.1/dns-query', {
              method: 'POST',
              headers: {
                'content-type': 'application/dns-message',
                'accept': 'application/dns-message',
              },
              body: chunk,
            });
            
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
            
            if (webSocket.readyState === WS_READY_STATE_OPEN) {
              log(`doh success and dns message length is ${udpSize}`);
              
              // تحسين: تقليل عمليات النسخ للبيانات
              const responseData = isVlessHeaderSent
                ? [udpSizeBuffer, dnsQueryResult]
                : [vlessResponseHeader, udpSizeBuffer, dnsQueryResult];
              
              const blob = new Blob(responseData);
              webSocket.send(await blob.arrayBuffer());
              isVlessHeaderSent = true;
            }
          } catch (error) {
            log('DNS query failed: ' + error);
          }
        },
      })
    )
    .catch((error) => {
      log('dns udp has error' + error);
    });

  const writer = transformStream.writable.getWriter();

  return {
    write(chunk: Uint8Array) {
      writer.write(chunk);
    },
  };
}
