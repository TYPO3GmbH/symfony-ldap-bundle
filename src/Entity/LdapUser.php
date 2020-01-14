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
     * {@inheritdoc}
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * {@inheritdoc}
     */
    public function getPassword()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getSalt()
    {
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function eraseCredentials()
    {
    }
}
