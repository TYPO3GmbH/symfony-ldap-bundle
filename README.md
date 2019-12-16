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

```yaml
# config/packages/security.yaml
security:
    providers:
        typo3_org_ldap:
            id: ldap.typo3.org.user.provider
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            anonymous: true
            form_login_ldap:
                login_path: login # Set your own login path here
                check_path: login # Set your own login path here
                csrf_token_generator: security.csrf.token_manager
                service: Symfony\Component\Ldap\Ldap
                dn_string: 'ou=people,dc=typo3,dc=org'
                query_string: '(&(objectClass=inetOrgPerson)(uid={username}))'
                search_dn: '%env(LDAP_SEARCH_USER)%' # set to the same value as ldap_search_user in your ldap.yaml
                search_password: '%env(LDAP_SEARCH_PASSWORD)%' # set to the same value as ldap_search_password in your ldap.yaml
                success_handler: T3G\Bundle\LdapBundle\Security\AuthenticationSuccessHandler
            logout:
                path: /logout # Set your own logout path here
                target: home # Set your own logout redirect route path here
```