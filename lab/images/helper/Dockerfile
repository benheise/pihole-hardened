# One helper image for the lab's upstream DNS server, list server and clients.
# Same pinned Alpine as the main Dockerfile; Renovate updates both together.
# renovate: datasource=docker depName=docker.io/library/alpine
ARG BASE_IMAGE=docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
FROM ${BASE_IMAGE}
RUN apk add --no-cache bind-tools curl dnsmasq jq python3
COPY sntp.py /usr/local/bin/sntp.py
