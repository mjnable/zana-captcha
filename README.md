# mj-zana/captcha

CAPTCHA providers for Zana applications: Cloudflare Turnstile, Google
reCAPTCHA (v2 and v3) and hCaptcha, behind mj-zana/security's
`#[VerifyHuman]`. The provider is chosen by configuration, so one can
replace another without changing code.

```
composer require mj-zana/captcha symfony/http-client nyholm/psr7
```

The providers are asked through a PSR-18 HTTP client, which the application
installs and registers; no provider SDK is needed:

```php
$services->singleton(\Psr\Http\Client\ClientInterface::class, static fn () => new \Symfony\Component\HttpClient\Psr18Client(
    \Symfony\Component\HttpClient\HttpClient::create(['max_connect_duration' => 2, 'timeout' => 3, 'max_duration' => 5]),
));
```

Bound it: a connect timeout (Symfony 8.1 or later), a read timeout and a total duration. Never wrap it in a
retrying client: a retried token is a reused one, and providers refuse it.

## Configuration

```php
// config/captcha.php
return [
    'provider' => 'turnstile',   // or recaptcha_v2, recaptcha_v3, hcaptcha
    // secret and site_key from the environment: APP_CAPTCHA__SECRET, APP_CAPTCHA__SITE_KEY
];
```

Register `CaptchaServiceProvider`, protect the handler, and print the widget
in the form:

```php
#[Route('/contact', methods: ['POST'], middleware: [BotVerificationMiddleware::class])]
#[VerifyHuman(action: 'contact')]
public function send(ServerRequestInterface $request): View|ResponseInterface { … }
```

```php
<form method="post">
    <?= $this->csrf_field('contact') ?>
    …
    <?= $this->captcha_widget('contact', $csp_nonce) ?>
</form>
```

- **reCAPTCHA v3** gives a score: `#[VerifyHuman(action: 'checkout', minimumScore: 0.5)]`.
  Its widget asks for a token when the form is sent.
- **Content-Security-Policy:** the widget needs the provider's script and
  frame. `check` says what to add to `http.security_headers.csp` when the
  policy blocks them, since a blocked widget would refuse every visitor.
- **When the provider cannot be asked,** or says the secret is wrong, the
  post is refused (`security.bot.on_unavailable: 'allow'` lets it through)
  and logged; it is never taken for the visitor being a bot.
- **Tests run without the network:** register mj-zana/security's
  `FakeBotVerifier` as `BotVerifierInterface`, or a PSR-18 client that
  answers from a list.

`check`: `captcha.config` (no provider, an unknown one, a missing secret or
site key), `captcha.http_client` (no PSR-18 client), `captcha.csp` (the
policy blocks the widget).

Documentation: [security](https://github.com/mjnable/zana-docs/blob/main/guides/security.md#new-in-225-bot-verification).
