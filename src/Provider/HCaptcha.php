<?php

declare(strict_types=1);

namespace Zana\Captcha\Provider;

/**
 * hCaptcha: a checkbox, or invisible; no score outside its enterprise plan.
 * The site key is sent with the token, so a token from another site is
 * refused by hCaptcha itself.
 */
final class HCaptcha extends SiteVerify
{
    public function field(): string
    {
        return 'h-captcha-response';
    }

    public function endpoint(): string
    {
        return 'https://api.hcaptcha.com/siteverify';
    }

    public function script(): string
    {
        return 'https://js.hcaptcha.com/1/api.js';
    }

    public function cspSources(): array
    {
        $hosts = ['https://hcaptcha.com', 'https://*.hcaptcha.com'];

        return ['script-src' => $hosts, 'frame-src' => $hosts, 'style-src' => $hosts, 'connect-src' => $hosts];
    }

    protected function element(?string $action, ?string $nonce): string
    {
        return '<div class="h-captcha" data-sitekey="' . self::e($this->siteKey) . '"></div>';
    }

    protected function extraFields(): array
    {
        return ['sitekey' => $this->siteKey];
    }
}
