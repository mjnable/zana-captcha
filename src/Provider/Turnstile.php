<?php

declare(strict_types=1);

namespace Zana\Captcha\Provider;

/**
 * Cloudflare Turnstile: usually invisible, no score. Its token names the
 * action given to the widget, and the hostname.
 */
final class Turnstile extends SiteVerify
{
    public function reportsAction(): bool
    {
        return true;
    }

    public function field(): string
    {
        return 'cf-turnstile-response';
    }

    public function endpoint(): string
    {
        return 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    }

    public function script(): string
    {
        return 'https://challenges.cloudflare.com/turnstile/v0/api.js';
    }

    public function cspSources(): array
    {
        return ['script-src' => ['https://challenges.cloudflare.com'], 'frame-src' => ['https://challenges.cloudflare.com']];
    }

    protected function element(?string $action, ?string $nonce): string
    {
        return '<div class="cf-turnstile" data-sitekey="' . self::e($this->siteKey) . '"' . ($action === null ? '' : ' data-action="' . self::e($action) . '"') . '></div>';
    }
}
