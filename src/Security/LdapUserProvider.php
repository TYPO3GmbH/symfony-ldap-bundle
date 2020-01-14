<?php
declare(strict_types=1);

/*
 * This file is part of the package t3g/symfony-ldap-bundle.
 * For the full copyright and license information, please read the
 * LICENSE file that was distributed with this source code.
 */

namespace T3G\Bundle\LdapBundle\Security;

use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\LdapInterface;
use Symfony\Component\Ldap\Security\LdapUser;
use Symfony\Component\Ldap\Security\LdapUserProvider as SymfonyLdapUserProvider;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;

class LdapUserProvider extends SymfonyLdapUserProvider
{
    /**
     * @var array
     */
    private $roleMapping;

    /**
     * @var array
     */
    private $defaults;

    public function __construct(LdapInterface $ldap, string $baseDn, string $searchDn = null, string $searchPassword = null, array $defaultRoles = [], string $uidKey = null, string $filter = null, string $passwordAttribute = null, array $extraFields = [], array $roleMapping = [])
    {
        parent::__construct($ldap, $baseDn, $searchDn, $searchPassword, $defaultRoles, $uidKey, $filter, $passwordAttribute, $extraFields);
        $this->roleMapping = $roleMapping;
        $this->defaults = $defaultRoles;
    }

    /**
     * Creates the user object, assigns roles from isMemberOf attribute
     * and sets display name from LDAP attribute.
     *
     * @param string $username
     * @param Entry $entry
     * @return LdapUser
     */
    protected function loadUser($username, Entry $entry): LdapUser
    {
        $uid = $this->getAttributeValue($entry, 'uid');
        if (!$entry->hasAttribute('isMemberOf')) {
            return new LdapUser(
                $entry,
                $uid,
                null,
                $this->defaults
            );
        }

        $isMemberOfValues = $entry->getAttribute('isMemberOf') ?? [];
        $hasRoles = array_intersect_key($this->roleMapping, array_flip($isMemberOfValues));
        $roles = array_merge($this->defaults, $hasRoles);

        if (0 === count($roles)) {
            throw new UsernameNotFoundException('You do not have permission to use this application');
        }

        /** @var LdapUser $user */
        $user = new LdapUser(
            $entry,
            $uid,
            null,
            $roles
        );

        if (!$this->supportsClass(get_class($user))) {
            throw new \RuntimeException('Userclass must be of type ' . LdapUser::class . ' or a child class.');
        }

        return $user;
    }

    /**
     * Fetches a required unique attribute value from an LDAP entry.
     *
     * @param Entry $entry
     * @param string $attribute
     * @return mixed
     */
    private function getAttributeValue(Entry $entry, $attribute)
    {
        if (!$entry->hasAttribute($attribute)) {
            throw new InvalidArgumentException(sprintf('Missing attribute "%s" for user "%s".', $attribute, $entry->getDn()));
        }

        $values = $entry->getAttribute($attribute) ?? [];

        if (1 !== count($values)) {
            throw new InvalidArgumentException(sprintf('Attribute "%s" has multiple values.', $attribute));
        }

        return $values[0];
    }
}
