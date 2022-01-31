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

# Podman cannot exceed 65533, this sets the maximum which we don't care about
# for testing this module.
cat > /usr/share/samba/setup/idmap_init.ldif << EOF
dn: CN=CONFIG
cn: CONFIG
lowerBound: 655
upperBound: 65533

dn: @INDEXLIST
@IDXATTR: xidNumber
@IDXATTR: objectSid

dn: CN=S-1-5-32-544
cn: S-1-5-32-544
objectClass: sidMap
objectSid: S-1-5-32-544
type: ID_TYPE_BOTH
xidNumber: 655
distinguishedName: CN=S-1-5-32-544
EOF

samba-tool domain provision \
    --use-rfc2307 \
    --realm="${AD_REALM}" \
    --domain="${AD_REALM%%.*}" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --adminpass="${AD_PASSWORD}" \
    --option="ldap server require strong auth = allow_sasl_over_tls" \
    --option="ldap ssl = start tls" \
    --option="vfs objects = acl_xattr xattr_tdb" \
    --option="idmap config * : range = 655-65533"

cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

samba --debug-stderr --foreground --no-process-group
