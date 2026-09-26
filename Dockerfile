# Pipeline app image: `docker compose run --rm --no-deps app send <ИдФайл>.xml` (see docker-compose.yml).
# Pure JS, no native deps, so it builds for the host platform (the КриптоАРМ Server image is amd64-only).
# No `# syntax=` line: nothing here needs a newer frontend than BuildKit's builtin one, so the build pulls
# no unpinned frontend image (as docker/cryptoarm-server/Dockerfile). The base is pinned by tag + index
# digest (multi-arch; == node:22-bookworm-slim on 2026-09-24): bump both together.

FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --from=build /app/dist ./dist
# The Diadoc refresh token file lives here on a named volume; a fresh volume inherits this ownership.
# /work is where the УПД files are mounted, so `send <name>.xml` takes a bare file name.
RUN mkdir -p /var/lib/app/diadoc /work \
  && chown node:node /var/lib/app/diadoc \
  && chmod 700 /var/lib/app/diadoc
USER node
WORKDIR /work
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["--help"]
