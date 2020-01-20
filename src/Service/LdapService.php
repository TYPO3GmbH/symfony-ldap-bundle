<?php
declare(strict_types=1);

/*
 * This file is part of the package t3g/symfony-ldap-bundle.
 * For the full copyright and license information, please read the
 * LICENSE file that was distributed with this source code.
 */

namespace T3G\Bundle\LdapBundle\Service;

use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\LdapInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;

class LdapService
{
    /**
     * @var LdapInterface
     */
    private $ldap;

    /**
     * @var string
     */
    private $searchDn;

    /**
     * @var string|null
     */
    private $searchPassword;

    /**
     * @var string
     */
    private $baseDn;

    /**
     * @param LdapInterface $ldap
     * @param string $baseDn
     * @param string $searchDn
     * @param string $searchPassword
     */
    public function __construct(
        LdapInterface $ldap,
        string $baseDn,
        string $searchDn,
        string $searchPassword
    ) {
        $this->ldap = $ldap;
        $this->searchDn = $searchDn;
        $this->searchPassword = $searchPassword;
        $this->baseDn = $baseDn;
    }

    /**
     * @param string $username
     * @return Entry
     * @throws UsernameNotFoundException
     * @trows ConnectionException
     */
    public function findUserByName(string $username): Entry
    {
        $this->ldap->bind($this->searchDn, $this->searchPassword);
        $username = $this->ldap->escape($username, '', LdapInterface::ESCAPE_FILTER);
        $query = str_replace('{username}', $username, '(uid={username})');
        $search = $this->ldap->query($this->baseDn, $query);

        $entries = $search->execute();
        $count = \count($entries);

        if (0 === $count) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found.', $username));
        }

        if (1 < $count) {
            throw new UsernameNotFoundException('More than one user found');
        }

        return $entries[0];
    }
}
