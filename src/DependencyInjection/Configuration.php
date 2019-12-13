<?php
declare(strict_types=1);

/*
 * This file is part of the package t3g/symfony-ldap-bundle.
 * For the full copyright and license information, please read the
 * LICENSE file that was distributed with this source code.
 */

namespace T3G\Bundle\LdapBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder('t3g-ldap');
        $treeBuilder->getRootNode()
            ->children()
            ->scalarNode('ldap_host')
            ->defaultValue('ldap.typo3.org')
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('ldap_port')
            ->defaultValue(636)
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('ldap_search_user')
            ->defaultValue('uid=foo,dc=example,dc=com')
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('ldap_search_password')
            ->defaultValue('bar')
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('ldap_base_dn')
            ->defaultValue('ou=people,dc=typo3,dc=org')
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('ldap_encryption')
            ->defaultValue('ssl')
            ->cannotBeEmpty()
            ->end()
            ->scalarNode('ldap_version')
            ->defaultValue(3)
            ->cannotBeEmpty()
            ->end()
            ->arrayNode('ldap_default_roles')
            ->scalarPrototype()->end()
            ->defaultValue(['ROLE_USER'])
            ->end()
            ->arrayNode('ldap_role_mapping')
            ->scalarPrototype()->end()
            ->defaultValue(['typo3.com-gmbh' => 'ROLE_ADMIN'])
            ->end()
            ->end()
            ->end()
        ;
        return $treeBuilder;
    }
}
