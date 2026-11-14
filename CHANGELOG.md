# Changelog

All Zana packages share one version number and are released together. A release that did
not change this package is not listed.

## 2.25.1 — Unreleased

### Fixed

- `check` reported a Content-Security-Policy with sources scoped to a path, such as `https://www.google.com/recaptcha/`
  as Google documents them, as blocking the widget. Paths are now read as CSP reads them: one ending in `/` covers what
  lies under it, one without covers that path only.
- reCAPTCHA's sources are Google's documented ones: scoped to `/recaptcha/`, with the frame host
  `recaptcha.google.com` and `connect-src`, which 2.25.0 did not ask for.
- No HTTP client, or a provider answering that the secret is missing or wrong, is a misconfiguration (mj-zana/security
  2.25.1), so it is refused even with `security.bot.on_unavailable: allow`; an unset or unknown `captcha.provider` too.

### Added

- The providers say what they report: all their hostnames; Turnstile and reCAPTCHA v3 their actions.
- The README shows the HTTP client bounded: a connect timeout, a read timeout, a total duration, no retries.

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
