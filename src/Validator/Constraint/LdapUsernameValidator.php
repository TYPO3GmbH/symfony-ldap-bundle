<?php
declare(strict_types=1);

/*
 * This file is part of the package t3g/symfony-ldap-bundle.
 * For the full copyright and license information, please read the
 * LICENSE file that was distributed with this source code.
 */

namespace T3G\Bundle\LdapBundle\Validator\Constraint;

use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;
use Symfony\Component\Validator\Exception\UnexpectedValueException;
use T3G\Bundle\LdapBundle\Service\LdapService;

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
        if (!$constraint instanceof LdapUsername) {
            throw new UnexpectedTypeException($constraint, LdapUsername::class);
        }

        if (!is_scalar($value) && !(\is_object($value) && method_exists($value, '__toString'))) {
            throw new UnexpectedValueException($value, 'string');
        }

        $value = (string)$value;

        try {
            $this->ldapService->findUserByName($value);
        } catch (UsernameNotFoundException $e) {
            $this->context->buildViolation($constraint->message)
                ->setParameter('{{ value }}', $value)
                ->addViolation();
        } catch (ConnectionException $e) {
            $this->context->buildViolation('There was an issue contacting the LDAP server.')
                ->addViolation();
        }
    }
}
