# Replaces dperson/torproxy:latest, abandoned since 2020. Its bundled Tor carried directory
# authority signing keys old enough that it could no longer validate a current consensus —
# it looped forever at "Bootstrapped 30%" with
# "Consensus not signed by sufficient number of requested authorities".
# Alpine's tor package tracks upstream, so the keys stay current.
FROM alpine:3.21

RUN apk add --no-cache tor curl

COPY torrc /etc/tor/torrc

USER tor
EXPOSE 9050

# Bootstrapping to a usable circuit takes ~30-60s, hence the generous start period.
# Exit through the SOCKS port itself — that is the only thing connectors actually use,
# so it is the only thing worth asserting.
HEALTHCHECK --interval=60s --timeout=20s --start-period=90s --retries=3 \
  CMD curl -fs --socks5-hostname 127.0.0.1:9050 -m 15 https://check.torproject.org/api/ip \
      | grep -q '"IsTor":true' || exit 1

ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
