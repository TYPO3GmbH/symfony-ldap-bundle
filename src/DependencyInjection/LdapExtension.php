<?php

/*
 * This file is part of the package t3g/symfony-ldap-bundle.
 * For the full copyright and license information, please read the
 * LICENSE file that was distributed with this source code.
 */

namespace T3G\Bundle\LdapBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

class LdapExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);
        $container->setParameter('t3g.ldap.config', $config);
        $container->setParameter('t3g.ldap.config.ldap_host', $config['ldap_host']);
        $container->setParameter('t3g.ldap.config.ldap_port', $config['ldap_port']);
        $container->setParameter('t3g.ldap.config.ldap_encryption', $config['ldap_encryption']);
        $container->setParameter('t3g.ldap.config.ldap_version', $config['ldap_version']);
        $container->setParameter('t3g.ldap.config.ldap_base_dn', $config['ldap_base_dn']);
        $container->setParameter('t3g.ldap.config.ldap_search_user', $config['ldap_search_user']);
        $container->setParameter('t3g.ldap.config.ldap_search_password', $config['ldap_search_password']);
        $container->setParameter('t3g.ldap.config.ldap_default_roles', $config['ldap_default_roles']);
        $container->setParameter('t3g.ldap.config.ldap_role_mapping', $config['ldap_role_mapping']);
        $container->setParameter('t3g.ldap.config.ldap_user_class', $config['ldap_user_class']);
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yaml');
    }
}
