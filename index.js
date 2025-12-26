const express = require("express");
const app = express();
const axios = require("axios");
const os = require('os');
const fs = require("fs");
const path = require("path");
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const { execSync } = require('child_process');
const http = require('http');
const httpProxy = require('http-proxy');

// ==================== WARP 配置部分 ====================
// 全局WARP配置（强制全流量走WARP）
const warpConfig = {
  name: '',
  v46url: 'https://icanhazip.com',
  warpUrl: 'https://ygkkk-warp.renky.eu.org',
  agsbxDir: path.join(process.env.HOME || '/root', 'agsbx'),
  // WARP默认参数
  defaultWarp: {
    wpv6: '2606:4700:110:8d8d:1845:c39f:2dd5:a03a',
    pvk: '52cuYFgCJXp0LAq7+nWJIbCXXgU9eGggOc+Hlfz5u6A=',
    res: '[215, 69, 233]'
  },
  // WARP端点配置
  warpEndpoints: {
    ipv4: '162.159.192.1',
    ipv6: '[2606:4700:d0::a29f:c001]'
  }
};

// 确保目录存在
function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

// 执行HTTP请求（替代curl/wget）
function fetchUrl(url) {
  try {
    // 优先使用curl，超时5秒
    return execSync(`curl -s5m -k ${url}`, { timeout: 5000 }).toString().trim();
  } catch (e) {
    try {
      // curl失败则用wget，超时3秒
      return execSync(`wget -qO- --timeout=3 --tries=2 ${url}`, { timeout: 3000 }).toString().trim();
    } catch (err) {
      return '';
    }
  }
}

// 获取服务器IPv4/IPv6地址
function getV4V6() {
  const v4 = fetchUrl(`curl -s4m5 -k ${warpConfig.v46url}`) || fetchUrl(`wget -4 --tries=2 -qO- ${warpConfig.v46url}`);
  const v6 = fetchUrl(`curl -s6m5 -k ${warpConfig.v46url}`) || fetchUrl(`wget -6 --tries=2 -qO- ${warpConfig.v46url}`);
  return { v4, v6 };
}

// 获取WARP参数（仅保留核心逻辑，无分支判断）
function getWarpParams() {
  let warpData = fetchUrl(warpConfig.warpUrl);
  let pvk, wpv6, res;

  // 解析远程WARP参数，失败则用默认值
  if (warpData && warpData.includes('ygkkk')) {
    pvk = warpData.match(/Private_key：([^\n]+)/)?.[1]?.trim() || warpConfig.defaultWarp.pvk;
    wpv6 = warpData.match(/IPV6：([^\n]+)/)?.[1]?.trim() || warpConfig.defaultWarp.wpv6;
    res = warpData.match(/reserved：([^\n]+)/)?.[1]?.trim() || warpConfig.defaultWarp.res;
  } else {
    pvk = warpConfig.defaultWarp.pvk;
    wpv6 = warpConfig.defaultWarp.wpv6;
    res = warpConfig.defaultWarp.res;
  }

  // 强制所有流量走WARP（移除所有分支，固定出站标签）
  const x1outtag = 'warp-out';
  const x2outtag = 'warp-out';
  const xip = '"::/0", "0.0.0.0/0"'; // 所有IPv4+IPv6
  const wap = 'warp';
  const wxryx = 'ForceIPv6v4'; // 强制双栈优先

  // 自动选择WARP端点（IPv6优先，无则用IPv4）
  const { v6 } = getV4V6();
  const v6Ok = !!v6;
  const xendip = v6Ok ? warpConfig.warpEndpoints.ipv6 : warpConfig.warpEndpoints.ipv4;

  return {
    pvk, wpv6, res,
    x1outtag, x2outtag,
    xip, wap, wxryx,
    xendip,
    v4: getV4V6().v4,
    v6: getV4V6().v6
  };
}
// ==================== WARP 配置部分结束 ====================

// 环境变量配置
const UPLOAD_URL = process.env.UPLOAD_URL || '';      // 节点或订阅自动上传地址
const PROJECT_URL = process.env.PROJECT_URL || '';    // 项目访问地址
const AUTO_ACCESS = process.env.AUTO_ACCESS || false; // 是否自动访问项目URL保持活跃
const FILE_PATH = process.env.FILE_PATH || './tmp';   // 临时文件存储目录路径
const SUB_PATH = process.env.SUB_PATH || 'sub';       // 订阅链接访问路径
const PORT = process.env.SERVER_PORT || process.env.PORT || 3000; // 内部HTTP服务端口
const EXTERNAL_PORT = process.env.EXTERNAL_PORT || 7860; // 外部代理服务器端口
const UUID = process.env.UUID || '4b3e2bfe-bde1-5def-d035-0cb572bbd046'; // Xray用户UUID
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';  // 哪吒监控服务器地址
const NEZHA_PORT = process.env.NEZHA_PORT || '';      // 哪吒v0监控服务器端口
const NEZHA_KEY = process.env.NEZHA_KEY || '';        // 哪吒监控客户端密钥
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || '';    // Cloudflare Argo隧道域名
const ARGO_AUTH = process.env.ARGO_AUTH || '';        // Argo隧道认证信息
const CFIP = process.env.CFIP || 'cdns.doon.eu.org';  // CDN回源IP地址
const CFPORT = process.env.CFPORT || 443;             // CDN回源端口
const NAME = process.env.NAME || '';                  // 节点名称前缀

// 创建运行文件夹
if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH);
  console.log(`${FILE_PATH} is created`);
} else {
  console.log(`${FILE_PATH} already exists`);
}

// 生成随机6位字符文件名
function generateRandomName() {
  const characters = 'abcdefghijklmnopqrstuvwxyz';
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

// 全局常量
const npmName = generateRandomName();
const webName = generateRandomName();
const botName = generateRandomName();
const phpName = generateRandomName();
let npmPath = path.join(FILE_PATH, npmName);
let phpPath = path.join(FILE_PATH, phpName);
let webPath = path.join(FILE_PATH, webName);
let botPath = path.join(FILE_PATH, botName);
let subPath = path.join(FILE_PATH, 'sub.txt');
let listPath = path.join(FILE_PATH, 'list.txt');
let bootLogPath = path.join(FILE_PATH, 'boot.log');
let configPath = path.join(FILE_PATH, 'config.json');

// 创建HTTP代理
const proxy = httpProxy.createProxyServer();
const proxyServer = http.createServer((req, res) => {
  const path = req.url;
  
  if (path.startsWith('/vless-argo') || 
      path.startsWith('/vmess-argo') || 
      path.startsWith('/trojan-argo') ||
      path === '/vless' || 
      path === '/vmess' || 
      path === '/trojan') {
    proxy.web(req, res, { target: 'http://localhost:3001' });
  } else {
    proxy.web(req, res, { target: `http://localhost:${PORT}` });
  }
});

// WebSocket代理处理
proxyServer.on('upgrade', (req, socket, head) => {
  const path = req.url;
  
  if (path.startsWith('/vless-argo') || 
      path.startsWith('/vmess-argo') || 
      path.startsWith('/trojan-argo')) {
    proxy.ws(req, socket, head, { target: 'http://localhost:3001' });
  } else {
    proxy.ws(req, socket, head, { target: `http://localhost:${PORT}` });
  }
});

// 启动代理服务器
proxyServer.listen(EXTERNAL_PORT, () => {
  console.log(`Proxy server is running on port:${EXTERNAL_PORT}!`);
  console.log(`HTTP traffic -> localhost:${PORT}`);
  console.log(`Xray traffic -> localhost:3001`);
});

// 根路由 - 提供外部index.html文件或显示Hello world!
app.get("/", function(req, res) {
  const indexPath = path.join(__dirname, 'index.html');
  
  // 检查index.html文件是否存在
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.send("Hello world!");
  }
});

// 删除历史节点
function deleteNodes() {
  try {
    if (!UPLOAD_URL) return;
    if (!fs.existsSync(subPath)) return;

    let fileContent;
    try {
      fileContent = fs.readFileSync(subPath, 'utf-8');
    } catch {
      return null;
    }

    const decoded = Buffer.from(fileContent, 'base64').toString('utf-8');
    const nodes = decoded.split('\n').filter(line => 
      /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line)
    );

    if (nodes.length === 0) return;

    axios.post(`${UPLOAD_URL}/api/delete-nodes`, 
      JSON.stringify({ nodes }),
      { headers: { 'Content-Type': 'application/json' } }
    ).catch((error) => { 
      return null; 
    });
    return null;
  } catch (err) {
    return null;
  }
}

// 清理历史文件
function cleanupOldFiles() {
  try {
    const files = fs.readdirSync(FILE_PATH);
    files.forEach(file => {
      const filePath = path.join(FILE_PATH, file);
      try {
        const stat = fs.statSync(filePath);
        if (stat.isFile()) {
          fs.unlinkSync(filePath);
        }
      } catch (err) {
        // 忽略错误
      }
    });
  } catch (err) {
    // 忽略错误
  }
}

// 生成Xray配置文件（整合WARP配置，强制全流量走WARP）
async function generateConfig() {
  // 获取WARP参数
  const warpParams = getWarpParams();
  
  const config = {
    log: { 
      access: '/dev/null', 
      error: '/dev/null', 
      loglevel: 'none' 
    },
    dns: {
      servers: [
        "https+local://8.8.8.8/dns-query",
        "https+local://1.1.1.1/dns-query",
        "8.8.8.8",
        "1.1.1.1"
      ],
      queryStrategy: "UseIP",
      disableCache: false
    },
    inbounds: [
      { 
        port: 3001,
        protocol: 'vless', 
        settings: { 
          clients: [{ id: UUID, flow: 'xtls-rprx-vision' }], 
          decryption: 'none', 
          fallbacks: [
            { dest: 3002 }, 
            { path: "/vless-argo", dest: 3003 }, 
            { path: "/vmess-argo", dest: 3004 }, 
            { path: "/trojan-argo", dest: 3005 }
          ] 
        }, 
        streamSettings: { network: 'tcp' } 
      },
      { 
        port: 3002, 
        listen: "127.0.0.1", 
        protocol: "vless", 
        settings: { 
          clients: [{ id: UUID }], 
          decryption: "none" 
        }, 
        streamSettings: { 
          network: "tcp", 
          security: "none" 
        } 
      },
      { 
        port: 3003, 
        listen: "127.0.0.1", 
        protocol: "vless", 
        settings: { 
          clients: [{ id: UUID, level: 0 }], 
          decryption: "none" 
        }, 
        streamSettings: { 
          network: "ws", 
          security: "none", 
          wsSettings: { path: "/vless-argo" } 
        }, 
        sniffing: { 
          enabled: true, 
          destOverride: ["http", "tls", "quic"], 
          metadataOnly: false 
        } 
      },
      { 
        port: 3004, 
        listen: "127.0.0.1", 
        protocol: "vmess", 
        settings: { 
          clients: [{ id: UUID, alterId: 0 }] 
        }, 
        streamSettings: { 
          network: "ws", 
          wsSettings: { path: "/vmess-argo" } 
        }, 
        sniffing: { 
          enabled: true, 
          destOverride: ["http", "tls", "quic"], 
          metadataOnly: false 
        } 
      },
      { 
        port: 3005, 
        listen: "127.0.0.1", 
        protocol: "trojan", 
        settings: { 
          clients: [{ password: UUID }] 
        }, 
        streamSettings: { 
          network: "ws", 
          security: "none", 
          wsSettings: { path: "/trojan-argo" } 
        }, 
        sniffing: { 
          enabled: true, 
          destOverride: ["http", "tls", "quic"], 
          metadataOnly: false 
        } 
      }
    ],
    outbounds: [
      // 保留原有direct出站（备用）
      {
        protocol: "freedom",
        tag: "direct",
        settings: {
          domainStrategy: warpParams.wxryx
        }
      },
      // 添加WARP WireGuard出站
      {
        tag: 'x-warp-out',
        protocol: 'wireguard',
        settings: {
          secretKey: warpParams.pvk,
          address: [
            '172.16.0.2/32',
            `${warpParams.wpv6}/128`
          ],
          peers: [
            {
              publicKey: 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=',
              allowedIPs: [
                '0.0.0.0/0',
                '::/0'
              ],
              endpoint: `${warpParams.xendip}:2408`
            }
          ],
          reserved: JSON.parse(warpParams.res)
        }
      },
      // WARP代理出站（所有流量走这个）
      {
        tag: 'warp-out',
        protocol: 'freedom',
        settings: {
          domainStrategy: warpParams.wxryx
        },
        proxySettings: {
          tag: 'x-warp-out'
        }
      },
      // 保留blackhole出站
      {
        protocol: "blackhole",
        tag: "block"
      }
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: [
        // 强制所有IP流量走WARP
        {
          type: 'field',
          ip: JSON.parse(`[${warpParams.xip}]`),
          network: 'tcp,udp',
          outboundTag: warpParams.x1outtag
        },
        // 兜底规则：所有流量走WARP
        {
          type: 'field',
          network: 'tcp,udp',
          outboundTag: warpParams.x2outtag
        }
      ]
    }
  };
  
  // 写入配置文件
  fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));
  
  // 输出WARP配置信息
  console.log(`✅ Xray WARP配置已生成，强制所有流量走WARP`);
  console.log(`🔑 WARP Private Key: ${warpParams.pvk}`);
  console.log(`🌐 WARP IPv6: ${warpParams.wpv6}`);
  console.log(`🔌 WARP端点: ${warpParams.xendip}:2408`);
}

// 判断系统架构
function getSystemArchitecture() {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return 'arm';
  } else {
    return 'amd';
  }
}

// 下载文件
function downloadFile(fileName, fileUrl, callback) {
  const filePath = fileName; 
  
  if (!fs.existsSync(FILE_PATH)) {
    fs.mkdirSync(FILE_PATH, { recursive: true });
  }
  
  const writer = fs.createWriteStream(filePath);

  axios({
    method: 'get',
    url: fileUrl,
    responseType: 'stream',
  })
    .then(response => {
      response.data.pipe(writer);

      writer.on('finish', () => {
        writer.close();
        console.log(`Download ${path.basename(filePath)} successfully`);
        callback(null, filePath);
      });

      writer.on('error', err => {
        fs.unlink(filePath, () => { });
        const errorMessage = `Download ${path.basename(filePath)} failed: ${err.message}`;
        console.error(errorMessage);
        callback(errorMessage);
      });
    })
    .catch(err => {
      const errorMessage = `Download ${path.basename(filePath)} failed: ${err.message}`;
      console.error(errorMessage);
      callback(errorMessage);
    });
}

// 下载并运行依赖文件
async function downloadFilesAndRun() {  
  const architecture = getSystemArchitecture();
  const filesToDownload = getFilesForArchitecture(architecture);

  if (filesToDownload.length === 0) {
    console.log(`Can't find a file for the current architecture`);
    return;
  }

  const downloadPromises = filesToDownload.map(fileInfo => {
    return new Promise((resolve, reject) => {
      downloadFile(fileInfo.fileName, fileInfo.fileUrl, (err, filePath) => {
        if (err) {
          reject(err);
        } else {
          resolve(filePath);
        }
      });
    });
  });

  try {
    await Promise.all(downloadPromises);
  } catch (err) {
    console.error('Error downloading files:', err);
    return;
  }

  // 授权文件
  function authorizeFiles(filePaths) {
    const newPermissions = 0o775;
    filePaths.forEach(absoluteFilePath => {
      if (fs.existsSync(absoluteFilePath)) {
        fs.chmod(absoluteFilePath, newPermissions, (err) => {
          if (err) {
            console.error(`Empowerment failed for ${absoluteFilePath}: ${err}`);
          } else {
            console.log(`Empowerment success for ${absoluteFilePath}: ${newPermissions.toString(8)}`);
          }
        });
      }
    });
  }
  const filesToAuthorize = NEZHA_PORT ? [npmPath, webPath, botPath] : [phpPath, webPath, botPath];
  authorizeFiles(filesToAuthorize);

  // 运行ne-zha
  if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      const tlsPorts = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
      const nezhatls = tlsPorts.has(port) ? 'true' : 'false';
      
      const configYaml = `
client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${nezhatls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;
      
      fs.writeFileSync(path.join(FILE_PATH, 'config.yaml'), configYaml);
      
      const command = `nohup ${phpPath} -c "${FILE_PATH}/config.yaml" >/dev/null 2>&1 &`;
      try {
        await exec(command);
        console.log(`${phpName} is running`);
        await new Promise((resolve) => setTimeout(resolve, 1000));
      } catch (error) {
        console.error(`php running error: ${error}`);
      }
    } else {
      let NEZHA_TLS = '';
      const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
      if (tlsPorts.includes(NEZHA_PORT)) {
        NEZHA_TLS = '--tls';
      }
      const command = `nohup ${npmPath} -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
      try {
        await exec(command);
        console.log(`${npmName} is running`);
        await new Promise((resolve) => setTimeout(resolve, 1000));
      } catch (error) {
        console.error(`npm running error: ${error}`);
      }
    }
  } else {
    console.log('NEZHA variable is empty,skip running');
  }

  // 运行xr-ay
  const command1 = `nohup ${webPath} -c ${FILE_PATH}/config.json >/dev/null 2>&1 &`;
  try {
    await exec(command1);
    console.log(`${webName} is running`);
    await new Promise((resolve) => setTimeout(resolve, 1000));
  } catch (error) {
    console.error(`web running error: ${error}`);
  }

  // 运行cloud-fared
  if (fs.existsSync(botPath)) {
    let args;

    if (ARGO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
      args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}`;
    } else if (ARGO_AUTH.includes('TunnelSecret')) {
      // 确保 YAML 配置已生成
      if (!fs.existsSync(path.join(FILE_PATH, 'tunnel.yml'))) {
        console.log('Waiting for tunnel.yml configuration...');
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
      args = `tunnel --edge-ip-version auto --config ${FILE_PATH}/tunnel.yml run`;
    } else {
      args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${FILE_PATH}/boot.log --loglevel info --url http://localhost:${EXTERNAL_PORT}`;
    }

    try {
      await exec(`nohup ${botPath} ${args} >/dev/null 2>&1 &`);
      console.log(`${botName} is running`);
      
      // 等待隧道启动
      console.log('Waiting for tunnel to start...');
      await new Promise((resolve) => setTimeout(resolve, 5000));
      
      // 检查隧道是否成功启动
      if (ARGO_AUTH.includes('TunnelSecret')) {
        // 对于固定隧道，检查进程是否在运行
        try {
          if (process.platform === 'win32') {
            await exec(`tasklist | findstr ${botName} > nul`);
          } else {
            await exec(`pgrep -f "[${botName.charAt(0)}]${botName.substring(1)}" > /dev/null`);
          }
          console.log('Tunnel is running successfully');
        } catch (error) {
          console.error('Tunnel failed to start');
        }
      }
    } catch (error) {
      console.error(`Error executing command: ${error}`);
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 2000));
}

// 根据系统架构返回对应的url
function getFilesForArchitecture(architecture) {
  let baseFiles;
  if (architecture === 'arm') {
    baseFiles = [
      { fileName: webPath, fileUrl: "https://arm64.ssss.nyc.mn/web" },
      { fileName: botPath, fileUrl: "https://arm64.ssss.nyc.mn/bot" }
    ];
  } else {
    baseFiles = [
      { fileName: webPath, fileUrl: "https://amd64.ssss.nyc.mn/web" },
      { fileName: botPath, fileUrl: "https://amd64.ssss.nyc.mn/bot" }
    ];
  }

  if (NEZHA_SERVER && NEZHA_KEY) {
    if (NEZHA_PORT) {
      const npmUrl = architecture === 'arm' 
        ? "https://arm64.ssss.nyc.mn/agent"
        : "https://amd64.ssss.nyc.mn/agent";
        baseFiles.unshift({ 
          fileName: npmPath, 
          fileUrl: npmUrl 
        });
    } else {
      const phpUrl = architecture === 'arm' 
        ? "https://arm64.ssss.nyc.mn/v1" 
        : "https://amd64.ssss.nyc.mn/v1";
      baseFiles.unshift({ 
        fileName: phpPath, 
        fileUrl: phpUrl
      });
    }
  }

  return baseFiles;
}

// 获取固定隧道json - 确保YAML配置正确生成
function argoType() {
  if (!ARGO_AUTH || !ARGO_DOMAIN) {
    console.log("ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels");
    return;
  }

  if (ARGO_AUTH.includes('TunnelSecret')) {
    try {
      // 解析JSON获取TunnelID
      const tunnelConfig = JSON.parse(ARGO_AUTH);
      const tunnelId = tunnelConfig.TunnelID;
      
      fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), ARGO_AUTH);
      
      const tunnelYaml = `tunnel: ${tunnelId}
credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}
protocol: http2

ingress:
  - hostname: ${ARGO_DOMAIN}
    service: http://localhost:${EXTERNAL_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
`;
      
      fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
      console.log('Tunnel YAML configuration generated successfully');
    } catch (error) {
      console.error('Error generating tunnel configuration:', error);
    }
  } else {
    console.log("ARGO_AUTH mismatch TunnelSecret, use token connect to tunnel");
  }
}

// 获取isp信息
async function getMetaInfo() {
  try {
    const response1 = await axios.get('https://ipapi.co/json/', { timeout: 3000 });
    if (response1.data && response1.data.country_code && response1.data.org) {
      return `${response1.data.country_code}_${response1.data.org}`;
    }
  } catch (error) {
      try {
        // 备用 ip-api.com 获取isp
        const response2 = await axios.get('http://ip-api.com/json/', { timeout: 3000 });
        if (response2.data && response2.data.status === 'success' && response2.data.countryCode && response2.data.org) {
          return `${response2.data.countryCode}_${response2.data.org}`;
        }
      } catch (error) {
        // console.error('Backup API also failed');
      }
  }
  return 'Unknown';
}

// 获取临时隧道domain
async function extractDomains() {
  let argoDomain;

  if (ARGO_AUTH && ARGO_DOMAIN) {
    argoDomain = ARGO_DOMAIN;
    console.log('ARGO_DOMAIN:', argoDomain);
    await generateLinks(argoDomain);
  } else {
    try {
      const fileContent = fs.readFileSync(path.join(FILE_PATH, 'boot.log'), 'utf-8');
      const lines = fileContent.split('\n');
      const argoDomains = [];
      lines.forEach((line) => {
        const domainMatch = line.match(/https?:\/\/([^ ]*trycloudflare\.com)\/?/);
        if (domainMatch) {
          const domain = domainMatch[1];
          argoDomains.push(domain);
        }
      });

      if (argoDomains.length > 0) {
        argoDomain = argoDomains[0];
        console.log('ArgoDomain:', argoDomain);
        await generateLinks(argoDomain);
      } else {
        console.log('ArgoDomain not found, re-running bot to obtain ArgoDomain');
        fs.unlinkSync(path.join(FILE_PATH, 'boot.log'));
        async function killBotProcess() {
          try {
            if (process.platform === 'win32') {
              await exec(`taskkill /f /im ${botName}.exe > nul 2>&1`);
            } else {
              await exec(`pkill -f "[${botName.charAt(0)}]${botName.substring(1)}" > /dev/null 2>&1`);
            }
          } catch (error) {
            // 忽略输出
          }
        }
        killBotProcess();
        await new Promise((resolve) => setTimeout(resolve, 3000));
        const args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${FILE_PATH}/boot.log --loglevel info --url http://localhost:${EXTERNAL_PORT}`;
        try {
          await exec(`nohup ${botPath} ${args} >/dev/null 2>&1 &`);
          console.log(`${botName} is running`);
          await new Promise((resolve) => setTimeout(resolve, 3000));
          await extractDomains();
        } catch (error) {
          console.error(`Error executing command: ${error}`);
        }
      }
    } catch (error) {
      console.error('Error reading boot.log:', error);
    }
  }

  async function generateLinks(argoDomain) {
    // 获取ISP信息
    const ISP = await getMetaInfo();
    const nodeName = NAME ? `${NAME}-${ISP}` : ISP;

    return new Promise((resolve) => {
      setTimeout(() => {
        const VMESS = { v: '2', ps: `${nodeName}`, add: CFIP, port: CFPORT, id: UUID, aid: '0', scy: 'none', net: 'ws', type: 'none', host: argoDomain, path: '/vmess-argo?ed=2560', tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox'};
        const subTxt = `
vless://${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Fvless-argo%3Fed%3D2560#${nodeName}
  
vmess://${Buffer.from(JSON.stringify(VMESS)).toString('base64')}
  
trojan://${UUID}@${CFIP}:${CFPORT}?security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#${nodeName}
        `;
        console.log(Buffer.from(subTxt).toString('base64'));
        fs.writeFileSync(subPath, Buffer.from(subTxt).toString('base64'));
        console.log(`${FILE_PATH}/sub.txt saved successfully`);
        uploadNodes();
        
        app.get(`/${SUB_PATH}`, (req, res) => {
          const encodedContent = Buffer.from(subTxt).toString('base64');
          res.set('Content-Type', 'text/plain; charset=utf-8');
          res.send(encodedContent);
        });
        resolve(subTxt);
      }, 2000);
    });
  }
}

// 自动上传节点或订阅
async function uploadNodes() {
  if (UPLOAD_URL && PROJECT_URL) {
    const subscriptionUrl = `${PROJECT_URL}/${SUB_PATH}`;
    const jsonData = {
      subscription: [subscriptionUrl]
    };
    try {
        const response = await axios.post(`${UPLOAD_URL}/api/add-subscriptions`, jsonData, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response && response.status === 200) {
            console.log('Subscription uploaded successfully');
            return response;
        } else {
          return null;
        }
    } catch (error) {
        if (error.response) {
            if (error.response.status === 400) {
            }
        }
    }
  } else if (UPLOAD_URL) {
      if (!fs.existsSync(listPath)) return;
      const content = fs.readFileSync(listPath, 'utf-8');
      const nodes = content.split('\n').filter(line => /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line));

      if (nodes.length === 0) return;

      const jsonData = JSON.stringify({ nodes });

      try {
          const response = await axios.post(`${UPLOAD_URL}/api/add-nodes`, jsonData, {
              headers: { 'Content-Type': 'application/json' }
          });
          if (response && response.status === 200) {
            console.log('Nodes uploaded successfully');
            return response;
        } else {
            return null;
        }
      } catch (error) {
          return null;
      }
  } else {
      return;
  }
}

// 90s后删除相关文件
function cleanFiles() {
  setTimeout(() => {
    const filesToDelete = [bootLogPath, configPath, webPath, botPath];  
    
    if (NEZHA_PORT) {
      filesToDelete.push(npmPath);
    } else if (NEZHA_SERVER && NEZHA_KEY) {
      filesToDelete.push(phpPath);
    }

    if (process.platform === 'win32') {
      exec(`del /f /q ${filesToDelete.join(' ')} > nul 2>&1`, (error) => {
        console.clear();
        console.log('App is running');
        console.log('Thank you for using this script, enjoy!');
      });
    } else {
      exec(`rm -rf ${filesToDelete.join(' ')} >/dev/null 2>&1`, (error) => {
        console.clear();
        console.log('App is running');
        console.log('Thank you for using this script, enjoy!');
      });
    }
  }, 90000);
}
cleanFiles();

// 自动访问项目URL
async function AddVisitTask() {
  if (!AUTO_ACCESS || !PROJECT_URL) {
    console.log("Skipping adding automatic access task");
    return;
  }

  try {
    const response = await axios.post('https://oooo.serv00.net/add-url', {
      url: PROJECT_URL
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    console.log(`automatic access task added successfully`);
    return response;
  } catch (error) {
    console.error(`Add automatic access task faild: ${error.message}`);
    return null;
  }
}

// 主运行逻辑
async function startserver() {
  try {
    console.log('Starting server initialization...');
    
    deleteNodes();
    cleanupOldFiles();
    
    argoType();
    
    await generateConfig();
    
    await downloadFilesAndRun();
    
    await extractDomains();
    
    await AddVisitTask();
    
    console.log('Server initialization completed successfully');
  } catch (error) {
    console.error('Error in startserver:', error);
  }
}

app.listen(PORT, () => console.log(`HTTP service is running on internal port:${PORT}!`));

startserver().catch(error => {
  console.error('Unhandled error in startserver:', error);
});