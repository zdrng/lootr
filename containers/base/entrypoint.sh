#!/bin/sh
# Entry point of every scenario container: runs lootr with the scenario's
# environment. Container engines inject variables of their own (podman:
# `container`; podman and docker: `HOSTNAME`); they are removed so results
# are the same with both engines.
#
# Optional scenario hooks in /usr/local/lib/lootr-scenario/:
#   setup   run first, as the image's user (e.g. root creates sockets: a
#           socket cannot be stored in an image layer)
#   env     KEY=value lines exported into lootr's environment (secrets
#           generated at build time)
#   args    extra lootr arguments, one per line, appended to the command
#           line (e.g. `--config` layers of the scenario)
# With LOOTR_SCENARIO_USER set, lootr runs as that user (setpriv, with its
# groups and home) after the setup.
set -eu
unset container HOSTNAME
hooks=/usr/local/lib/lootr-scenario
if [ -x "$hooks/setup" ]; then
    "$hooks/setup"
fi
if [ -f "$hooks/env" ]; then
    set -a
    . "$hooks/env"
    set +a
fi
if [ -f "$hooks/args" ]; then
    while IFS= read -r arg; do
        set -- "$@" "$arg"
    done <"$hooks/args"
fi
if [ -n "${LOOTR_SCENARIO_USER:-}" ]; then
    user=$LOOTR_SCENARIO_USER
    unset LOOTR_SCENARIO_USER
    HOME=$(getent passwd "$user" | cut -d: -f6)
    export HOME
    exec setpriv --reuid="$user" --regid="$user" --init-groups /usr/local/bin/lootr "$@"
fi
exec /usr/local/bin/lootr "$@"
