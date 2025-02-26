const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const tls = require("tls");
const find = require("find");
const cluster = require("cluster");
const os = require("os");
const winston = require("winston");
const { exec } = require("child_process");

const config = require("./config.json");
const FIREWALL_RULE_NAME_PREFIX = "BLOCKED BY SENVAS";

const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ level, message, timestamp }) =>
      `[${timestamp}] [Process ${process.pid}] ${level}: ${message}`
    )
  ),
  transports: [new winston.transports.Console()]
});

const notFoundPage = fs.readFileSync(path.join(__dirname, "./html/error/404.html"), "utf-8");
const forbiddenPage = fs.readFileSync(path.join(__dirname, "./html/error/403.html"), "utf-8");

const sslConfig = {
  "cache.senvas.my.id": {
    key: fs.readFileSync("./ssl/cache.senvas.my.id.pem"),
    cert: fs.readFileSync("./ssl/cache.senvas.my.id.pem")
  }
};

const allowedHosts = ["cache.senvas.my.id"];

const requestCounts = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const record = requestCounts.get(ip);
  if (!record) {
    requestCounts.set(ip, { count: 1, startTime: now });
    return false;
  }
  if (now - record.startTime > config.timeWindowMs) {
    record.count = 1;
    record.startTime = now;
    return false;
  } else {
    record.count++;
    if (record.count > config.maxRequests) {
      return true;
    }
    return false;
  }
}

function normalizeIp(ip) {
  if (ip.startsWith("::ffff:")) {
    return ip.replace("::ffff:", "");
  }
  return ip;
}

const blockedIps = new Set();
function blockIp(ip) {
  const normalizedIp = normalizeIp(ip);
  if (blockedIps.has(normalizedIp)) {
    logger.info(`IP ${normalizedIp} sudah ada di rule firewall, tidak menambahkan rule baru.`);
    return;
  }
  blockedIps.add(normalizedIp);
  const ruleName = `${FIREWALL_RULE_NAME_PREFIX} - ${normalizedIp}`;
  const direction = config.firewallDirection || "in";
  const cmd = `netsh advfirewall firewall add rule name="${ruleName}" dir=${direction} action=block remoteip=${normalizedIp}`;
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      logger.error(`Gagal memblokir IP ${normalizedIp}: ${error}`);
      blockedIps.delete(normalizedIp);
    } else {
      logger.info(`IP ${normalizedIp} diblokir dengan rule "${ruleName}".`);
    }
  });
}

const serverData = "Server Data Placeholder";

function requestHandler(req, res) {
  let ip = req.connection.remoteAddress;
  ip = normalizeIp(ip);

  if (checkRateLimit(ip)) {
    blockIp(ip);
    return req.connection.destroy();
  }
  
  if (req.connection.bytesRead > 4999) {
    blockIp(ip);
    return req.connection.destroy();
  }
  
  if (
    req.headers["content-length"] == "0" ||
    req.headers["content-length"] == 0 ||
    req.headers["content-type"] === "application/x-www-form-urlencoded\r\nX-Requested-With: XMLHttpRequest\r\n charset=utf-8\r\n"
  ) {
    blockIp(ip);
    return req.connection.destroy();
  }
  
  const filePath = path.join(__dirname, "htdocs", req.url);
  fs.readFile(filePath, (err, data) => {
    if (err) {
      if (err.code === "ENOENT") {
        if (
          req.url.startsWith("/cache") &&
          req.headers.accept === "**" &&
          allowedHosts.indexOf(req.headers.host) >= 0
        ) {
          logger.info("Missing file -> " + req.url);
        } else {
          res.writeHead(404, { "Content-Type": "text/html" });
          res.end(notFoundPage);
          blockIp(ip);
          return req.connection.destroy();
        }
      } else if (err.code === "EISDIR") {
        res.setHeader("Content-Type", "text/html");
        find.file(path.join(__dirname, "htdocs", req.url), (files) => {
          if (files.length < 1) {
            res.write("Directory does not contain any files");
            blockIp(ip);
            return req.connection.destroy();
          }
          if (req.url === "/cache/" || req.url === "/cache") {
            res.writeHead(403, { "Content-Type": "text/html" });
            res.end(forbiddenPage);
            blockIp(ip);
            return req.connection.destroy();
          }
          if (req.url === "/") {
            res.writeHead(301, { "Content-Type": "text/plain" });
            res.write("upp");
            res.end();
            blockIp(ip);
            return req.connection.destroy();
          }
          res.write(`<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
<head>
  <title>Index of ${req.url}</title>
</head>
<body>
  <h1>Index of ${req.url}</h1>
  <table>
    <tr><th colspan="5"><hr></th></tr>`);
          files.forEach((file) => {
            const relativePath = path.relative(
              path.join(__dirname, "htdocs", req.url),
              file
            );
            res.write(
              `<tr><td valign="top"><img src="/icons/unknown.png"></td><td><a href="${relativePath}">${relativePath}</a></td></tr>`
            );
          });
          res.write(`<tr><th colspan="5"><hr></th></tr>
  </table>
  <address>Node-JS HTTPS Server at ${req.headers.host} Port 443</address>
</body>
</html>`);
          res.end();
        });
      } else {
        return;
      }
    } else {
      if (req.url === "/growtopia/server_data.php") {
        if (req.method.toLowerCase() !== "post") {
          res.writeHead(403, { "Content-Type": "text/html" });
          res.end(forbiddenPage);
          blockIp(ip);
          return req.connection.destroy();
        }
        req.on("data", () => {
          res.writeHead(200, { "Content-Type": "text/html" });
          res.write(serverData, (writeErr) => {
            logger.info("Growtopia connection -> " + req.url);
            if (writeErr) {
              logger.error(writeErr);
            }
            res.end();
          });
        });
      } else {
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(data);
      }
    }
  });
}

const httpsOptions = {
  key: sslConfig["cache.senvas.my.id"].key,
  cert: sslConfig["cache.senvas.my.id"].cert,
  SNICallback: (domain, cb) => {
    const normalizedDomain = domain.replace(/^www\./, "");
    if (sslConfig[normalizedDomain]) {
      cb(null, tls.createSecureContext(sslConfig[normalizedDomain]));
    } else {
      cb(null, tls.createSecureContext(sslConfig["cache.senvas.my.id"]));
    }
  }
};

if (cluster.isMaster) {
  logger.info("Server V2 Started");
  logger.info("Server running on port 80");
  logger.info("Server running on port 443");
  const numCPUs = os.cpus().length;
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }
  cluster.on("exit", (worker, code, signal) => {
    cluster.fork();
  });
} else {
  const httpServer = http.createServer(requestHandler);
  httpServer.listen(80, () => {
    logger.info(`HTTP server listening on port 80 (Process ${process.pid})`);
  });
  const httpsServer = https.createServer(httpsOptions, requestHandler);
  httpsServer.setTimeout(10000);
  httpsServer.on("connection", (socket) => {
    socket.setTimeout(5000);
  });
  httpsServer.listen(443, () => {
    logger.info(`HTTPS server listening on port 443 (Process ${process.pid})`);
  });
}
