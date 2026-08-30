FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS build
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.30.4-alpine@sha256:93722936b82ec8a1178d48448e619226680d2de3706a1640800e186cd5fa7fd3
COPY infra/nginx/web.conf /etc/nginx/conf.d/default.conf
COPY infra/nginx/validate-web-tls.sh /docker-entrypoint.d/10-validate-web-tls.sh
USER root
RUN apk upgrade --no-cache libcrypto3 libssl3 \
    && chmod 0555 /docker-entrypoint.d/10-validate-web-tls.sh
USER 101:101
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8443
