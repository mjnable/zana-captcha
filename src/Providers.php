<?php

declare(strict_types=1);

namespace Zana\Captcha;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Zana\Captcha\Provider\HCaptcha;
use Zana\Captcha\Provider\ReCaptchaV2;
use Zana\Captcha\Provider\ReCaptchaV3;
use Zana\Captcha\Provider\SiteVerify;
use Zana\Captcha\Provider\Turnstile;

/**
 * The providers captcha.provider may name (2.25, FE-64), so one is replaced
 * by another with a setting.
 *
 * @api
 */
final class Providers
{
    /** @var array<string, class-string<SiteVerify>> */
    public const array ALL = [
        'turnstile' => Turnstile::class,
        'recaptcha_v2' => ReCaptchaV2::class,
        'recaptcha_v3' => ReCaptchaV3::class,
        'hcaptcha' => HCaptcha::class,
    ];

    public static function create(string $name, string $secret, string $siteKey, ?ClientInterface $client, RequestFactoryInterface $requests, StreamFactoryInterface $streams): SiteVerify
    {
        $class = self::ALL[$name] ?? throw new \InvalidArgumentException("captcha.provider is \"{$name}\", not one of " . implode(', ', array_keys(self::ALL)) . '.');

        return new $class($secret, $siteKey, $client, $requests, $streams);
    }
}
