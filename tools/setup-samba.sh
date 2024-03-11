#!/bin/bash -e

apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    acl \
    attr \
    dnsutils \
    krb5-config \
    krb5-user \
    ldb-tools \
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

DOMAIN_DN="$( echo "${AD_REALM,,}" | sed 's/\./,DC=/g; s/^/DC=/; s/,$//' )"
SCHEMA_DN="CN=Schema,CN=Configuration,${DOMAIN_DN}"

# Extends the schema for our tests
ldbadd \
    -H /var/lib/samba/private/sam.ldb \
    --option="dsdb:schema update allowed"=true \
    --interactive << EOF

dn: CN=psopenadBoolSingle,${SCHEMA_DN}
changetype: add
objectClass: attributeSchema
adminDescription: Test Attribute for Boolean Single
ldapDisplayName: psopenadBoolSingle
attributeId: 1.3.6.1.4.1.2312.66666.1
attributeSyntax: 2.5.5.8
omSyntax: 1
isSingleValued: TRUE
systemOnly: FALSE
isMemberOfPartialAttributeSet: FALSE
searchFlags: 0
showInAdvancedViewOnly: FALSE

dn: CN=psopenadBoolMulti,${SCHEMA_DN}
changetype: add
objectClass: attributeSchema
adminDescription: Test Attribute for Boolean Multi
ldapDisplayName: psopenadBoolMulti
attributeId: 1.3.6.1.4.1.2312.66666.2
attributeSyntax: 2.5.5.8
omSyntax: 1
isSingleValued: FALSE
systemOnly: FALSE
isMemberOfPartialAttributeSet: FALSE
searchFlags: 0
showInAdvancedViewOnly: FALSE

dn: CN=psopenadBytesSingle,${SCHEMA_DN}
changetype: add
objectClass: attributeSchema
adminDescription: Test Attribute for Bytes Single
ldapDisplayName: psopenadBytesSingle
attributeId: 1.3.6.1.4.1.2312.66666.3
attributeSyntax: 2.5.5.10
omSyntax: 4
isSingleValued: TRUE
systemOnly: FALSE
isMemberOfPartialAttributeSet: FALSE
searchFlags: 0
showInAdvancedViewOnly: FALSE

dn: CN=psopenadBytesMulti,${SCHEMA_DN}
changetype: add
objectClass: attributeSchema
adminDescription: Test Attribute for Bytes Multi
ldapDisplayName: psopenadBytesMulti
attributeId: 1.3.6.1.4.1.2312.66666.4
attributeSyntax: 2.5.5.10
omSyntax: 4
isSingleValued: FALSE
systemOnly: FALSE
isMemberOfPartialAttributeSet: FALSE
searchFlags: 0
showInAdvancedViewOnly: FALSE

dn: CN=psopenadDateTimeSingle,${SCHEMA_DN}
changetype: add
objectClass: attributeSchema
adminDescription: Test Attribute for DateTime Single
ldapDisplayName: psopenadDateTimeSingle
attributeId: 1.3.6.1.4.1.2312.66666.5
attributeSyntax: 2.5.5.11
omSyntax: 24
isSingleValued: TRUE
systemOnly: FALSE
isMemberOfPartialAttributeSet: FALSE
searchFlags: 0
showInAdvancedViewOnly: FALSE

dn: CN=psopenadDateTimeMulti,${SCHEMA_DN}
changetype: add
objectClass: attributeSchema
adminDescription: Test Attribute for DateTime Multi
ldapDisplayName: psopenadDateTimeMulti
attributeId: 1.3.6.1.4.1.2312.66666.6
attributeSyntax: 2.5.5.11
omSyntax: 24
isSingleValued: FALSE
systemOnly: FALSE
isMemberOfPartialAttributeSet: FALSE
searchFlags: 0
showInAdvancedViewOnly: FALSE

dn: CN=psopenadIntSingle,${SCHEMA_DN}
changetype: add
objectClass: attributeSchema
adminDescription: Test Attribute for Int Single
ldapDisplayName: psopenadIntSingle
attributeId: 1.3.6.1.4.1.2312.66666.7
attributeSyntax: 2.5.5.16
omSyntax: 65
isSingleValued: TRUE
systemOnly: FALSE
isMemberOfPartialAttributeSet: FALSE
searchFlags: 0
showInAdvancedViewOnly: FALSE

dn: CN=psopenadIntMulti,${SCHEMA_DN}
changetype: add
objectClass: attributeSchema
adminDescription: Test Attribute for Int Multi
ldapDisplayName: psopenadIntMulti
attributeId: 1.3.6.1.4.1.2312.66666.8
attributeSyntax: 2.5.5.16
omSyntax: 65
isSingleValued: FALSE
systemOnly: FALSE
isMemberOfPartialAttributeSet: FALSE
searchFlags: 0
showInAdvancedViewOnly: FALSE

dn: CN=psopenadStringSingle,${SCHEMA_DN}
changetype: add
objectClass: attributeSchema
adminDescription: Test Attribute for String Single
ldapDisplayName: psopenadStringSingle
attributeId: 1.3.6.1.4.1.2312.66666.9
attributeSyntax: 2.5.5.12
omSyntax: 64
isSingleValued: TRUE
systemOnly: FALSE
isMemberOfPartialAttributeSet: FALSE
searchFlags: 0
showInAdvancedViewOnly: FALSE

dn: CN=psopenadStringMulti,${SCHEMA_DN}
changetype: add
objectClass: attributeSchema
adminDescription: Test Attribute for String Multi
ldapDisplayName: psopenadStringMulti
attributeId: 1.3.6.1.4.1.2312.66666.10
attributeSyntax: 2.5.5.12
omSyntax: 64
isSingleValued: FALSE
systemOnly: FALSE
isMemberOfPartialAttributeSet: FALSE
searchFlags: 0
showInAdvancedViewOnly: FALSE

dn: CN=psopenadSDSingle,${SCHEMA_DN}
changetype: add
objectClass: attributeSchema
adminDescription: Test Attribute for SD Single
ldapDisplayName: psopenadSDSingle
attributeId: 1.3.6.1.4.1.2312.66666.11
attributeSyntax: 2.5.5.15
omSyntax: 66
isSingleValued: TRUE
systemOnly: FALSE
isMemberOfPartialAttributeSet: FALSE
searchFlags: 0
showInAdvancedViewOnly: FALSE

dn: CN=psopenadSDMulti,${SCHEMA_DN}
changetype: add
objectClass: attributeSchema
adminDescription: Test Attribute for SD Multi
ldapDisplayName: psopenadSDMulti
attributeId: 1.3.6.1.4.1.2312.66666.12
attributeSyntax: 2.5.5.15
omSyntax: 66
isSingleValued: FALSE
systemOnly: FALSE
isMemberOfPartialAttributeSet: FALSE
searchFlags: 0
showInAdvancedViewOnly: FALSE
EOF

ldbadd \
    -H /var/lib/samba/private/sam.ldb \
    --option="dsdb:schema update allowed"=true \
    --interactive << EOF

dn: CN=psopenADTesting,${SCHEMA_DN}
description: Test auxiliary class for PSOpenAD attribute tests
governsID: 1.3.6.1.4.1.2312.66666
ldapDisplayName: psopenADTesting
objectClass: classSchema
objectClassCategory: 3
subClassOf: top
systemOnly: FALSE
mayContain: psopenadBoolSingle
mayContain: psopenadBoolMulti
mayContain: psopenadBytesSingle
mayContain: psopenadBytesMulti
mayContain: psopenadDateTimeSingle
mayContain: psopenadDateTimeMulti
mayContain: psopenadIntSingle
mayContain: psopenadIntMulti
mayContain: psopenadStringSingle
mayContain: psopenadStringMulti
mayContain: psopenadSDSingle
mayContain: psopenadSDMulti
EOF

ldbmodify \
    -H /var/lib/samba/private/sam.ldb \
    --option="dsdb:schema update allowed"=true \
    --interactive << EOF

dn: CN=top,${SCHEMA_DN}
changetype: modify
add: auxiliaryClass
auxiliaryClass: psopenADTesting
EOF

# FUTURE: Move this to the test suite once New-OpenAD* has been implented
samba-tool group add \
    TestGroup

samba-tool group add \
    TestGroupSub

samba-tool user create \
    TestGroupMember Password01!

samba-tool user create \
    TestGroupSubMember Password01!

samba-tool group addmembers \
    TestGroup \
    TestGroupSub,TestGroupMember

samba-tool group addmembers \
    TestGroupSub \
    TestGroupSubMember

samba --debug-stdout --foreground --no-process-group
