// backend/middleware/viewerAuth.js
// TEMP viewer guard. Replace with real auth later.
export function requireViewer(req, res, next) {
  const id = req.headers["x-viewer-id"] || req.cookies?.viewerId || null;
  const username = req.headers["x-viewer-name"] || req.cookies?.viewerName || null;

  if (!id || !username) {
    return res.status(401).json({ ok: false, error: "viewer_unauthorized" });
  }

  req.viewer = { id, username };
  next();
}
