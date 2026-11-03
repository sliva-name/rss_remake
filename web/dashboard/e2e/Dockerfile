# Browser check of the dashboard. The base image carries the browsers matching
# the Playwright version pinned in package-lock.json.
FROM mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f
WORKDIR /check
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY smoke.mjs ./
USER pwuser
ENTRYPOINT ["node", "smoke.mjs", "/out"]
