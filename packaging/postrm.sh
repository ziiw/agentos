#!/bin/sh
# Takes the AppArmor profile back out when the package goes (not on upgrades).
# $1: "remove" or "purge" (deb); the number of versions left, 0 (rpm).
case "$1" in
    remove | purge | 0)
        if [ -e /etc/apparmor.d/agentos ]; then
            if [ -w /sys/kernel/security/apparmor/.remove ]; then
                printf agentos > /sys/kernel/security/apparmor/.remove 2>/dev/null || true
            fi
            rm -f /etc/apparmor.d/agentos
        fi
        ;;
esac
exit 0
