FROM nginxinc/nginx-unprivileged:1.30.4-alpine@sha256:44e36330f74d4f3a1d4e222acca9e23b401fb87811a7597024502bb759c4dd49

USER root
RUN rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /etc/nginx/tls \
    && chown 101:101 /etc/nginx/tls
COPY infra/nginx/email-platform.conf.template /etc/nginx/edge-template.conf
COPY infra/nginx/slots/blue.conf /etc/nginx/edge-routing/active-slot.conf
COPY infra/nginx/slots/blue.conf /etc/nginx/edge-routing-templates/blue.conf
COPY infra/nginx/slots/green.conf /etc/nginx/edge-routing-templates/green.conf
COPY infra/nginx/render-edge-config.sh /usr/local/bin/render-edge-config
RUN chmod 0444 /etc/nginx/edge-template.conf \
    /etc/nginx/edge-routing/active-slot.conf \
    /etc/nginx/edge-routing-templates/blue.conf \
    /etc/nginx/edge-routing-templates/green.conf \
    && chmod 0555 /usr/local/bin/render-edge-config

USER 101:101
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/render-edge-config"]
CMD ["nginx", "-g", "daemon off;"]
