# syntax=docker/dockerfile:1
# Pipeline app image: `docker compose run --rm app send <ИдФайл>.xml` (see docker-compose.yml).
# Pure JS, no native deps, so it builds for the host platform (the КриптоАРМ Server image is amd64-only).

FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim AS runtime
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
