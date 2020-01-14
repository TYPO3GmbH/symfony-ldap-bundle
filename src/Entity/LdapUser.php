<?php
declare(strict_types=1);

/*
 * This file is part of the package t3g/symfony-ldap-bundle.
 * For the full copyright and license information, please read the
 * LICENSE file that was distributed with this source code.
 */

namespace T3G\Bundle\LdapBundle\Entity;

use Symfony\Component\Security\Core\User\UserInterface;

class LdapUser implements UserInterface
{
    /**
     * @var string
     */
    private $username;

    /**
     * @var array
     */
    private $roles;

    /**
     * @var string|null Attribute 'displayName' from LDAP
     */
    private $displayName;

    public function __construct(
        string $username,
        ?string $displayName,
        array $roles = []
    ) {
        $this->username = $username;
        $this->displayName = $displayName;
        $this->roles = $roles;
    }

    public function __toString()
    {
        return $this->getUsername();
    }

    /**
     * Returns the roles granted to the user.
     *
     *     public function getRoles()
     *     {
     *         return ['ROLE_USER'];
     *     }
     *
     * Alternatively, the roles might be stored on a ``roles`` property,
     * and populated in any number of different ways when the user object
     * is created.
     *
     * @return (\Symfony\Component\Security\Core\Role\Role|string)[] The user roles
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * Returns the password used to authenticate the user.
     *
     * This should be the encoded password. On authentication, a plain-text
     * password will be salted, encoded, and then compared to this value.
     *
     * @return string|null The encoded password if any
     */
    public function getPassword()
    {
        return null;
    }

    /**
     * Returns the salt that was originally used to encode the password.
     *
     * This can return null if the password was not encoded using a salt.
     *
     * @return string|null The salt
     */
    public function getSalt()
    {
        return null;
    }

    /**
     * Returns the username used to authenticate the user.
     *
     * @return string The username
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Attribute 'displayName' from LDAP
     *
     * @return string|null
     */
    public function getDisplayName(): ?string
    {
        return $this->displayName;
    }

    /**
     * Removes sensitive data from the user.
     *
     * This is important if, at any given point, sensitive information like
     * the plain-text password is stored on this object.
     */
    public function eraseCredentials()
    {
    }
}
