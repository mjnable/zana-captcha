<?php

declare(strict_types=1);

namespace Zana\Captcha\Provider;

/**
 * Google reCAPTCHA v2, the "I'm not a robot" checkbox: no score, no action.
 */
class ReCaptchaV2 extends SiteVerify
{
    public function field(): string
    {
        return 'g-recaptcha-response';
    }

    public function endpoint(): string
    {
        return 'https://www.google.com/recaptcha/api/siteverify';
    }

    public function script(): string
    {
        return 'https://www.google.com/recaptcha/api.js';
    }

    public function cspSources(): array
    {
        return ['script-src' => ['https://www.google.com', 'https://www.gstatic.com'], 'frame-src' => ['https://www.google.com']];
    }

    protected function element(?string $action, ?string $nonce): string
    {
        return '<div class="g-recaptcha" data-sitekey="' . self::e($this->siteKey) . '"></div>';
    }
}
