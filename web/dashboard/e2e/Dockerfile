# Browser check of the dashboard. The base image carries the browsers matching
# the Playwright version pinned in package-lock.json.
FROM mcr.microsoft.com/playwright:v1.65.0-noble@sha256:6e3fb709361521eb27161606e6da6d2674e5e89fa16516cb37d6fdd91372273d
WORKDIR /check
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY smoke.mjs ./
USER pwuser
ENTRYPOINT ["node", "smoke.mjs", "/out"]
