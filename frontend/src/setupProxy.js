/**
 * CRA dev-server proxy.
 *
 * This file is consumed by Webpack DevServer (via `react-scripts start`)
 * EXCLUSIVELY. It is NOT included in the production bundle (`npm run
 * build` / `serve -s build`) and has zero effect in Kubernetes / Docker
 * Compose deployments where nginx (`/api/*` → backend) handles routing.
 *
 * Default target is `http://localhost:8000` because the only realistic
 * use of `npm start` is on a developer's host machine, where the backend
 * is reachable on localhost. The target can be overridden with the
 * `PROXY_TARGET` environment variable (e.g. `PROXY_TARGET=http://other-host:8000 npm start`).
 *
 * Why not `http://backend:8000`? That hostname only resolves inside the
 * Docker Compose network. Defaulting to it caused all `/api/*` requests
 * to fail with ENOTFOUND when running the dev-server on the host.
 */
const { createProxyMiddleware } = require('http-proxy-middleware');

const target = process.env.PROXY_TARGET || 'http://localhost:8000';

module.exports = function (app) {
  app.use(
    '/api',
    createProxyMiddleware({
      target,
      changeOrigin: true,
      logLevel: 'warn',
    })
  );
};
