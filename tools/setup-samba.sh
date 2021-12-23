#!/bin/bash -e

apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    acl \
    attr \
    dnsutils \
    krb5-config \
    krb5-user \
    ntp \
    samba \
    samba-dsdb-modules \
    samba-vfs-modules \
    winbind

rm /etc/samba/smb.conf

samba-tool domain provision \
    --use-rfc2307 \
    --realm="${AD_REALM}" \
    --domain="${AD_REALM%%.*}" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --adminpass="${AD_PASSWORD}" \
    --option="ldap server require strong auth = allow_sasl_over_tls"

cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

samba --debug-stderr --foreground --no-process-group
