"use strict";
// SR3 harness preload (--require): records and blocks every network primitive
// the collector process could use. The SR3 test asserts the report file stays
// empty — the collector must complete with zero egress attempts.
//
// Unix-domain-socket connects (an options object with `path`) are allowed:
// they are same-machine IPC — tsx itself uses one — not egress. Egress means
// TCP (host/port), TLS, UDP, or DNS resolution.
const fs = require("fs");
const net = require("net");
const tls = require("tls");
const dgram = require("dgram");
const dns = require("dns");

const out = process.env.NET_OBSERVE_OUT;
function report(kind, detail) {
  if (!out) return;
  try {
    fs.appendFileSync(out, JSON.stringify({ kind, detail: String(detail) }) + "\n");
  } catch {
    /* reporting must never mask the block below */
  }
}
function blocked(kind, detail) {
  report(kind, typeof detail === "object" ? JSON.stringify(detail) : detail);
  throw new Error(`SR3 test harness: network use blocked (${kind})`);
}

function isPipeConnect(args) {
  const a = args[0];
  if (typeof a === "string" && !/^\d+$/.test(a)) return true; // connect(path)
  if (Array.isArray(a)) return isPipeConnect(a); // normalized args array
  if (typeof a === "object" && a !== null && typeof a.path === "string") return true;
  return false;
}

// Single chokepoint for TCP: net.connect/createConnection and http(s) agents
// all end up in Socket.prototype.connect.
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function connectGuard(...args) {
  if (isPipeConnect(args)) return origConnect.apply(this, args);
  blocked("net.Socket.connect", args[0]);
};

tls.connect = (...args) => blocked("tls.connect", args[0]);
dgram.createSocket = (...args) => blocked("dgram.createSocket", args[0]);
dns.lookup = (...args) => blocked("dns.lookup", args[0]);
dns.resolve = (...args) => blocked("dns.resolve", args[0]);
if (dns.promises) {
  dns.promises.lookup = async (h) => blocked("dns.promises.lookup", h);
  dns.promises.resolve = async (h) => blocked("dns.promises.resolve", h);
}
