<?php
declare(strict_types=1);

/*
 * This file is part of the package t3g/symfony-ldap-bundle.
 * For the full copyright and license information, please read the
 * LICENSE file that was distributed with this source code.
 */

namespace T3G\Bundle\LdapBundle\Validator\Constraint;

use Symfony\Component\Validator\Constraint;

/**
 * @Annotation
 */
class LdapUsername extends Constraint
{
    /**
     * Any public properties become valid options for the annotation.
     * Then, use these in your validator class.
     *
     * @var string
     */
    public $message = '"{{ value }}" is not a valid user in the TYPO3.org LDAP directory.';
}
