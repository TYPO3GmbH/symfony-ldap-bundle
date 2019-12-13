# symfony-ldap-bundle
This package is used across various TYPO3 Symfony Applications to enable LDAP login with typo3.org.

## Installation
```bash
composer require t3g/symfony-ldap-bundle
```

## configuration

```yaml
# config/packages/ldap.yaml
ldap:
    ldap_host: 'ldap.typo3.org'
    ldap_port: 636
    # Override this variable from your .env file
    ldap_search_user: 'uid=foo,dc=example,dc=com'
    # Override this variable from your .env file
    ldap_search_password: 'bar'
    ldap_base_dn: 'ou=people,dc=typo3,dc=org'
    ldap_encryption: 'ssl'
    ldap_version: 3
    ldap_default_roles: ['ROLE_USER']
    ldap_role_mapping: 
        typo3.com-gmbh: 'ROLE_ADMIN'
```