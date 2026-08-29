FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43 AS build
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.30.4-alpine@sha256:44e36330f74d4f3a1d4e222acca9e23b401fb87811a7597024502bb759c4dd49
COPY infra/nginx/web.conf /etc/nginx/conf.d/default.conf
COPY infra/nginx/validate-web-tls.sh /docker-entrypoint.d/10-validate-web-tls.sh
USER root
RUN chmod 0555 /docker-entrypoint.d/10-validate-web-tls.sh
USER 101:101
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8443
