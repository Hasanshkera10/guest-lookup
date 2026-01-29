import fs from "fs";
import path from "path";
import crypto from "crypto";

function base64urlToBuffer(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}
function verify(token, secret) {
  const [body, sig] = String(token || "").split(".");
  if (!body || !sig) return false;

  const expected = crypto.createHmac("sha256", secret).update(body).digest();
  const given = base64urlToBuffer(sig);

  if (given.length !== expected.length) return false;
  return crypto.timingSafeEqual(given, expected);
}
function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const parts = raw.split(";").map(s => s.trim());
  const found = parts.find(p => p.startsWith(name + "="));
  if (!found) return null;
  return decodeURIComponent(found.slice(name.length + 1));
}

export default function handler(req, res) {
  const secret = process.env.AUTH_SECRET;
  if (!secret) return res.status(500).json({ error: "Missing AUTH_SECRET" });

  const token = getCookie(req, "gl_session");
  const authed = token ? verify(token, secret) : false;

  if (!authed) return res.status(401).json({ error: "Unauthorized" });

  const filePath = path.join(process.cwd(), "data", "guests.csv");
  if (!fs.existsSync(filePath)) return res.status(500).json({ error: "Missing data/guests.csv" });

  const csv = fs.readFileSync(filePath, "utf8");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).send(csv);
}


