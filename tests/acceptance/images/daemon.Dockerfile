# The daemon side of the acceptance rig. The daemon runs on its native host
# with no jail, so it is the release image plus the programs a remote command
# may be given: the carriers check that `git` and `python3` really answer from
# this side, and a missing one must be a SKIP at that carrier, not a silent
# pass.
FROM rsbx:ci

USER 0
RUN apt-get update \
 && apt-get install -y --no-install-recommends git python3 \
 && rm -rf /var/lib/apt/lists/* \
 && test -x /usr/bin/git \
 && test -x /usr/bin/python3
USER rsbx
