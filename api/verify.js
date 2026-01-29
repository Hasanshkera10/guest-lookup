import crypto from "crypto";

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function sign(payload, secret) {
  const body = base64url(JSON.stringify(payload));
  const sig = base64url(crypto.createHmac("sha256", secret).update(body).digest());
  return `${body}.${sig}`;
}

export default function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const { pin } = req.body || {};
  const expectedPin = process.env.GUEST_PIN;
  const secret = process.env.AUTH_SECRET;

  if (!expectedPin || !secret) {
    return res.status(500).json({ error: "Server not configured (missing env vars)." });
  }

  if (String(pin || "").trim() !== String(expectedPin).trim()) {
    return res.status(401).json({ ok: false, error: "Invalid PIN" });
  }

  const token = sign({ iat: Date.now() }, secret);

  // 24 hours session
  res.setHeader("Set-Cookie", [
    `gl_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60 * 60 * 24}`
  ]);

  return res.status(200).json({ ok: true });
}

