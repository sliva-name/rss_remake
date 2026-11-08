# syntax=docker/dockerfile:1
# Platform images. Each final target holds one binary on a distroless base: no
# shell, no package manager, a non-root user. Base images are pinned by digest.

FROM node:24.22.2-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d AS dashboard
WORKDIR /src/web/dashboard
COPY web/dashboard/package.json web/dashboard/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY api/openapi /src/api/openapi
COPY web/dashboard ./
RUN npm run api && npm run build

FROM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/ ./cmd/server ./cmd/agent
# Empty directories owned by the runtime user. A new named volume takes the
# ownership of the directory it is mounted over.
RUN install -d -o 65532 -g 65532 -m 0700 /out/data/pki /out/data/state && \
    install -d -o 65532 -g 65532 -m 0755 /out/data/ca

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329 AS server
COPY --from=build /out/server /usr/local/bin/dataguard-server
COPY --from=dashboard /src/web/dashboard/dist /srv/dashboard
COPY --from=build --chown=65532:65532 /out/data/pki /var/lib/dataguard/pki
COPY --from=build --chown=65532:65532 /out/data/ca /var/lib/dataguard/ca
ENV DG_PKI_DIR=/var/lib/dataguard/pki DG_WEB_DIR=/srv/dashboard DG_API_ADDR=:8080 DG_AGENT_ADDR=:8443
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/dataguard-server"]
CMD ["serve"]

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329 AS agent
COPY --from=build /out/agent /usr/local/bin/dataguard-agent
COPY --from=build --chown=65532:65532 /out/data/state /var/lib/dataguard
ENTRYPOINT ["/usr/local/bin/dataguard-agent"]
CMD ["run", "--config", "/etc/dataguard/agent.yaml"]
