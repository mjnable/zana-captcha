# Changelog

All Zana packages share one version number and are released together. A release that did
not change this package is not listed.

## 2.25.0 — 2026-11-14

First release (FE-64). CAPTCHA providers behind mj-zana/security's `#[VerifyHuman]`:

- Cloudflare Turnstile, Google reCAPTCHA v2 and v3 (with its score) and hCaptcha, chosen by `captcha.provider`, with
  `captcha.secret` and `captcha.site_key` from the environment.
- Asked through the application's PSR-18 client: one HTTPS POST of the secret, the token and the client address.
  When the provider cannot be asked, answers something unreadable, or says the secret is wrong, the answer is
  unavailable, never "bot".
- `captcha_widget($action, $csp_nonce)` with mj-zana/view prints the provider's script and widget, escaped; the
  reCAPTCHA v3 widget asks for a token when the form is sent.
- `check`: `captcha.config`, `captcha.http_client`, and `captcha.csp` when the Content-Security-Policy would block the
  widget, which would refuse every visitor.

Requires PHP 8.5 or later.
