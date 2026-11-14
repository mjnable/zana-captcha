<?php

declare(strict_types=1);

namespace Zana\Captcha;

use Zana\Security\Bot\BotVerdict;
use Zana\Security\Bot\BotVerifierInterface;

/**
 * The verifier while captcha.provider is not set, or names no provider: it
 * asks nobody, and answers unavailable, so #[VerifyHuman] refuses requests
 * rather than let them through (2.25). `check` says why (captcha.config).
 *
 * @internal
 */
final readonly class Unconfigured implements BotVerifierInterface
{
    public function __construct(private string $why)
    {
    }

    public function field(): string
    {
        return 'captcha-response';
    }

    public function scores(): bool
    {
        return false;
    }

    public function verify(string $token, ?string $clientIp = null, ?string $action = null): BotVerdict
    {
        return BotVerdict::unavailable($this->why);
    }
}
