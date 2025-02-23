import https from "https";
import http from "http";
import fs from "fs";
import path from "path";
import os from "os";
import chalk from "chalk";
import winston from "winston";
import { exec } from "child_process";
import { fileURLToPath } from 'url'; 
import { ipLimiterConfig } from "./config.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.clear();
console.log(chalk.blueBright(`
███████╗███████╗███╗   ██╗██╗   ██╗ █████╗ ███████╗
██╔════╝██╔════╝████╗  ██║██║   ██║██╔══██╗██╔════╝
███████╗█████╗  ██╔██╗ ██║██║   ██║███████║███████╗
╚════██║██╔══╝  ██║╚██╗██║██║   ██║██╔══██║╚════██║
███████║███████╗██║ ╚████║╚██████╔╝██║  ██║███████║
╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
`));
console.log(chalk.yellow("📌 Status Server: Starting..."));

const logger = winston.createLogger({
    level: "info",
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ level, message, timestamp }) => {
            return `[${timestamp}] [Process ${process.pid}] ${level}: ${message}`;
        })
    ),
    transports: [new winston.transports.Console()]
});

const blacklist = new Map();
const requestCounts = new Map();

function addAddress(ip) {
    blacklist.set(ip, Date.now() + ipLimiterConfig.banDuration);
    if (ipLimiterConfig.permanentBan) {
        exec(`netsh advfirewall firewall add rule name="Block-${ip}" dir=in action=block remoteip=${ip}`, (err) => {
            if (err) logger.error(`Failed to block IP: ${ip}`);
            else logger.info(`Permanently blocked IP: ${ip}`);
        });
    }
}

function requestHandler(req, res) {
    let ip = req.connection.remoteAddress;

    if (blacklist.has(ip)) {
        if (Date.now() > blacklist.get(ip)) {
            blacklist.delete(ip);
        } else {
            logger.warn(`Blocked IP: ${ip}`);
            return req.connection.destroy();
        }
    }

    const requestCount = requestCounts.get(ip) || 0;
    if (requestCount > ipLimiterConfig.maxRequestsPerSecond) {
        addAddress(ip);
        logger.warn(`DDoS detected from IP: ${ip}`);
        return req.connection.destroy();
    }

    requestCounts.set(ip, requestCount + 1);
    setTimeout(() => {
        requestCounts.set(ip, requestCounts.get(ip) - 1);
    }, 1000);

    fs.readFile(__dirname + "/htdocs/" + req.url, function (err, data) {
        if (err) {
            res.writeHead(404, { "Content-Type": "text/html" });
            res.end("404 Not Found");
            return req.connection.destroy();
        }
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(data);
    });
}

http.createServer(requestHandler).listen(80, () => {
    console.log(chalk.green("HTTP Server Running on Port 80"));
});

https.createServer({
    key: fs.readFileSync("./ssl/www.growtopia1.com.key"),
    cert: fs.readFileSync("./ssl/www.growtopia1.com.crt")
}, requestHandler).listen(443, () => {
    console.log(chalk.green("HTTPS Server Running on Port 443"));
});

setTimeout(() => {
    console.log(chalk.green(" Status Server: RUNNING"));
}, 2000);
