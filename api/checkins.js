import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

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

export default async function handler(req, res) {
  const secret = process.env.AUTH_SECRET;
  if (!secret) return res.status(500).json({ error: "Missing AUTH_SECRET" });

  const token = getCookie(req, "gl_session");
  const authed = token ? verify(token, secret) : false;
  if (!authed) return res.status(401).json({ error: "Unauthorized" });

  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return res.status(500).json({ error: "Missing Supabase env vars" });

  const supabase = createClient(url, key, { auth: { persistSession: false } });
  const eventKey = process.env.EVENT_KEY || "default";
  const { data, error } = await supabase
    .from("checkins")
    .select("id, checked_in_at")
    .eq("event_key", eventKey);

  if (error) return res.status(500).json({ error: error.message });

  const checkins = {};
  for (const row of data || []) {
    if (row.id) checkins[row.id] = row.checked_in_at;
  }

  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ok: true, checkins: checkins || {} });
}
