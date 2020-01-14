<?php
declare(strict_types=1);

/*
 * This file is part of the package t3g/symfony-ldap-bundle.
 * For the full copyright and license information, please read the
 * LICENSE file that was distributed with this source code.
 */

namespace T3G\Bundle\LdapBundle\Security;

use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\LdapInterface;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use T3G\Bundle\LdapBundle\Entity\LdapUser;

class LdapUserProvider implements UserProviderInterface
{
    /**
     * @var LdapInterface
     */
    private $ldap;
    /**
     * @var string
     */
    private $baseDn;
    /**
     * @var string
     */
    private $searchDn;
    /**
     * @var string
     */
    private $searchPassword;
    /**
     * @var array
     */
    private $defaultRoles;
    /**
     * @var string
     */
    private $defaultSearch;
    /**
     * @var string
     */
    private $userClass;
    /**
     * @var array
     */
    private $roleMapping;

    /**
     * @param LdapInterface $ldap
     * @param string $basedn
     * @param string $searchDn
     * @param string $searchPassword
     * @param array $defaultRoles
     * @param array $roleMapping
     * @param string $userClass
     */
    public function __construct(
        LdapInterface $ldap,
        string $basedn,
        string $searchDn,
        string $searchPassword,
        array $defaultRoles,
        array $roleMapping,
        string $userClass
    ) {
        $this->ldap = $ldap;
        $this->baseDn = $basedn;
        $this->searchDn = $searchDn;
        $this->searchPassword = $searchPassword;
        $this->defaultRoles = $defaultRoles;
        $this->defaultSearch = '(uid={username})';
        $this->roleMapping = $roleMapping;
        $this->userClass = $userClass;
    }

    /**
     * Creates the user object, assigns roles from isMemberOf attribute
     * and sets display name from LDAP attribute.
     *
     * @param string $username
     * @param Entry $entry
     * @return UserInterface
     */
    protected function loadUser($username, Entry $entry): UserInterface
    {
        $displayName = null;
        $uid = $this->getAttributeValue($entry, 'uid');
        if ($entry->hasAttribute('displayName')) {
            $displayName = $this->getAttributeValue($entry, 'displayName');
        }
        if (!$entry->hasAttribute('isMemberOf')) {
            // If user does not have this attribute at all, he's just ROLE_USER
            return new $this->userClass(
                $this->getAttributeValue($entry, 'uid'),
                $displayName ?? $uid,
                $this->defaultRoles
            );
        }
        // If user has attribute, assign roles that map
        $isMemberOfValues = $entry->getAttribute('isMemberOf');
        $hasRoles = array_intersect_key($this->roleMapping, array_flip($isMemberOfValues));
        $roles = array_merge($this->defaultRoles, $hasRoles);

        if (0 === count($roles)) {
            throw new UsernameNotFoundException('You do not have permission to use this application');
        }

        /** @var LdapUser $user */
        $user = new $this->userClass(
            $this->getAttributeValue($entry, 'uid'),
            $displayName ?? $uid,
            $roles
        );

        if (!$this->supportsClass($user)) {
            throw new \RuntimeException('Userclass must be of type ' . LdapUser::class . ' or a child class.');
        }

        return $user;
    }

    /**
     * Loads the user for the given username.
     *
     * This method must throw UsernameNotFoundException if the user is not
     * found.
     *
     * @param string $username The username
     *
     * @return UserInterface
     *
     * @throws UsernameNotFoundException if the user is not found
     */
    public function loadUserByUsername($username)
    {
        try {
            $this->ldap->bind($this->searchDn, $this->searchPassword);
            $username = $this->ldap->escape($username, '', LdapInterface::ESCAPE_FILTER);
            $query = str_replace('{username}', $username, $this->defaultSearch);
            $search = $this->ldap->query($this->baseDn, $query);
        } catch (ConnectionException $e) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found.', $username), 0, $e);
        }

        $entries = $search->execute();
        $count = \count($entries);

        if (0 === $count) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found.', $username));
        }

        if (1 < $count) {
            throw new UsernameNotFoundException('More than one user found');
        }

        $entry = $entries[0];

        $username = $this->getAttributeValue($entry, 'uid');

        return $this->loadUser($username, $entry);
    }

    /**
     * Refreshes the user.
     *
     * It is up to the implementation to decide if the user data should be
     * totally reloaded (e.g. from the database), or if the UserInterface
     * object can just be merged into some internal array of users / identity
     * map.
     *
     * @return UserInterface
     *
     * @throws UnsupportedUserException  if the user is not supported
     * @throws UsernameNotFoundException if the user is not found
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$this->supportsClass($user)) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', \get_class($user)));
        }

        return new $this->userClass($user->getUsername(), $user->getDisplayName(), $user->getRoles());
    }

    /**
     * Whether this provider supports the given user class.
     *
     * @param string $class
     *
     * @return bool
     */
    public function supportsClass($class)
    {
        return $class instanceof LdapUser;
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

        $values = $entry->getAttribute($attribute) ?? 0;

        if (1 !== count($values)) {
            throw new InvalidArgumentException(sprintf('Attribute "%s" has multiple values.', $attribute));
        }

        return $values[0];
    }
}
