<?php

declare(strict_types=1);

namespace Zana\Captcha\Provider;

/**
 * Google reCAPTCHA v3: invisible, with a score from 0.0 (a bot) to 1.0 (a
 * person), for #[VerifyHuman(minimumScore: …)], and the action. The widget
 * asks for a token when the form is sent and puts it in a hidden field; its
 * script carries the CSP nonce.
 */
final class ReCaptchaV3 extends ReCaptchaV2
{
    public function scores(): bool
    {
        return true;
    }

    /**
     * Its widget runs an inline script, so script-src needs the nonce (or
     * 'unsafe-inline'), and the template must pass $csp_nonce.
     */
    public function cspSources(): array
    {
        $sources = parent::cspSources();
        $sources['script-src'][] = '{nonce}';

        return $sources;
    }

    public function script(): string
    {
        return 'https://www.google.com/recaptcha/api.js?render=' . rawurlencode($this->siteKey);
    }

    protected function element(?string $action, ?string $nonce): string
    {
        $id = 'zana-recaptcha-' . bin2hex(random_bytes(4));
        $settings = json_encode(['key' => $this->siteKey, 'action' => $action ?? 'submit', 'id' => $id], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);

        return '<input type="hidden" name="' . self::e($this->field()) . '" id="' . self::e($id) . '">'
            . '<script' . ($nonce === null ? '' : ' nonce="' . self::e($nonce) . '"') . '>'
            . '(function(s){var i=document.getElementById(s.id),f=i&&i.form,sent=false;if(!f){return;}'
            . 'f.addEventListener("submit",function(e){if(sent){return;}e.preventDefault();'
            . 'grecaptcha.ready(function(){grecaptcha.execute(s.key,{action:s.action}).then(function(t){i.value=t;sent=true;f.requestSubmit?f.requestSubmit():f.submit();});});});'
            . '})(' . $settings . ');</script>';
    }
}
