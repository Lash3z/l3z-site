export function requestLogger(req, _res, next) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${req.method} ${req.originalUrl}`, {
    query: req.query,
    body: req.body
  });
  next();
}
