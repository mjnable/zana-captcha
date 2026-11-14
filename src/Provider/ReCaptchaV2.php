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
        // As Google's reCAPTCHA FAQ lists them (2.25.1): scoped to /recaptcha/, with the second frame host and connect-src.
        return [
            'script-src' => ['https://www.google.com/recaptcha/', 'https://www.gstatic.com/recaptcha/'],
            'frame-src' => ['https://www.google.com/recaptcha/', 'https://recaptcha.google.com/recaptcha/'],
            'connect-src' => ['https://www.google.com/recaptcha/'],
        ];
    }

    protected function element(?string $action, ?string $nonce): string
    {
        return '<div class="g-recaptcha" data-sitekey="' . self::e($this->siteKey) . '"></div>';
    }
}
