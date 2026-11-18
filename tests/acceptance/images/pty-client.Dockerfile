# The client side of the interactive-terminal carrier. The pty harness opens
# its own pseudo-terminals from python3, so this image only differs from the
# release image by carrying python3 and the procps tools the harness reads.
FROM rsbx:ci

USER 0
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 procps util-linux \
 && rm -rf /var/lib/apt/lists/* \
 && test -x /usr/bin/python3
USER rsbx
