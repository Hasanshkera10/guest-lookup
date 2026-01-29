export default function handler(req, res) {
  res.setHeader("Set-Cookie", [
    "gl_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  ]);
  res.status(200).json({ ok: true });
}
