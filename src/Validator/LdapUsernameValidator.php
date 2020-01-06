<?php

/*
 * This file is part of the package t3g/symfony-ldap-bundle.
 * For the full copyright and license information, please read the
 * LICENSE file that was distributed with this source code.
 */

namespace T3G\Bundle\LdapBundle\Validator;

use T3G\Bundle\LdapBundle\Service\LdapService;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

class LdapUsernameValidator extends ConstraintValidator
{
    /**
     * @var LdapService
     */
    private $ldapService;

    public function __construct(LdapService $ldapService)
    {
        $this->ldapService = $ldapService;
    }

    public function validate($value, Constraint $constraint)
    {
        /* @var $constraint LdapUsername */

        if (null === $value || '' === $value) {
            return;
        }

        try {
            $this->ldapService->findUserByName($value);
        } catch (UsernameNotFoundException $e) {
            $this->context->buildViolation($constraint->message)
                ->setParameter('{{ value }}', $value)
                ->addViolation();
        }
    }
}
