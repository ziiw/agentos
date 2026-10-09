#!/bin/sh
# Where AppArmor 4 restricts unprivileged user namespaces (Ubuntu 23.10+),
# load a profile that allows them for /usr/bin/agent only. Elsewhere: nothing.
set -e
if [ -e /etc/apparmor.d/abi/4.0 ] && [ -d /sys/kernel/security/apparmor ] && command -v apparmor_parser >/dev/null 2>&1; then
    install -m 0644 /usr/share/agentos/apparmor/agentos /etc/apparmor.d/agentos
    apparmor_parser -r /etc/apparmor.d/agentos || echo "agentos: couldn't load /etc/apparmor.d/agentos; 'agent doctor' says what's missing" >&2
fi
exit 0
