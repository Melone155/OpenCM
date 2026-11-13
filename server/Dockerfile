# Build context: repository root  (docker build -f server/Dockerfile .)
# The server runs TypeScript directly via Node's built-in type stripping – no build step.

# Agent binaries for all platforms, served by the server (AGENT_BUNDLED_DIR) unless
# AGENT_DOWNLOAD_DIR contains its own. VERSION ends up in the binaries and version.txt
# (agents update themselves to it); "dev" builds are never offered as updates.
FROM golang:1.23-alpine AS agent
ARG VERSION=dev
WORKDIR /src
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ ./
RUN set -e; mkdir -p /out; \
    for os in linux windows darwin; do for arch in amd64 arm64; do \
      ext=""; [ "$os" = windows ] && ext=".exe"; \
      CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" \
        -o /out/opencm-agent-$os-$arch$ext . ; \
    done; done; \
    echo "$VERSION" > /out/version.txt

FROM node:24-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY server/package.json server/
COPY web/package.json web/
RUN npm ci --workspace server --omit=dev --include-workspace-root=false --ignore-scripts \
 && mkdir -p server/node_modules

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/server/node_modules ./server/node_modules
COPY server/package.json server/openapi.yaml ./server/
COPY server/drizzle ./server/drizzle
COPY server/src ./server/src
COPY --from=agent /out /app/agent-dist
ENV AGENT_BUNDLED_DIR=/app/agent-dist
RUN mkdir -p /data/files /data/pki && chown -R node:node /data
USER node
WORKDIR /app/server
EXPOSE 8080 8443
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/api/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/index.ts"]
