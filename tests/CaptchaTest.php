<?php

declare(strict_types=1);

namespace Zana\Captcha\Tests;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zana\Captcha\CaptchaCheck;
use Zana\Captcha\CaptchaServiceProvider;
use Zana\Captcha\Provider\HCaptcha;
use Zana\Captcha\Provider\ReCaptchaV2;
use Zana\Captcha\Provider\ReCaptchaV3;
use Zana\Captcha\Provider\SiteVerify;
use Zana\Captcha\Provider\Turnstile;
use Zana\Captcha\Providers;
use Zana\Captcha\Unconfigured;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Core\Application;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\Severity;
use Zana\Http\Exception\ForbiddenHttpException;
use Zana\Http\HttpServiceProvider;
use Zana\Http\SecurityHeadersMiddleware;
use Zana\Routing\Attribute\PublicRoute;
use Zana\Routing\Router;
use Zana\Routing\RoutingServiceProvider;
use Zana\Security\Attribute\VerifyHuman;
use Zana\Security\Bot\BotVerifierInterface;
use Zana\Security\Middleware\BotVerificationMiddleware;
use Zana\Security\SecurityServiceProvider;
use Zana\View\ViewHelpers;
use Zana\View\ViewServiceProvider;

/**
 * 2.25, FE-64: the CAPTCHA providers, asked through a PSR-18 client, never
 * the network in these tests; chosen by configuration; and check.
 */
final class CaptchaTest extends TestCase
{
    // ── Asking the provider ────────────────────────────────────────────────

    /**
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function providers(): iterable
    {
        yield 'turnstile' => ['turnstile', 'https://challenges.cloudflare.com/turnstile/v0/siteverify', 'cf-turnstile-response'];
        yield 'recaptcha_v2' => ['recaptcha_v2', 'https://www.google.com/recaptcha/api/siteverify', 'g-recaptcha-response'];
        yield 'recaptcha_v3' => ['recaptcha_v3', 'https://www.google.com/recaptcha/api/siteverify', 'g-recaptcha-response'];
        yield 'hcaptcha' => ['hcaptcha', 'https://api.hcaptcha.com/siteverify', 'h-captcha-response'];
    }

    #[DataProvider('providers')]
    public function testEachProviderIsAskedWithOnePost(string $name, string $endpoint, string $field): void
    {
        $client = new FakeClient(['{"success": true}']);
        $verifier = self::provider($name, $client);

        $this->assertTrue($verifier->verify('the-token', '198.51.100.7', 'contact')->human);
        $this->assertSame($field, $verifier->field());
        $request = $client->requests[0];
        $this->assertSame(['POST', $endpoint], [$request->getMethod(), (string) $request->getUri()]);
        $this->assertSame('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        parse_str((string) $request->getBody(), $sent);
        $expected = ['secret' => 's3cret', 'response' => 'the-token', 'remoteip' => '198.51.100.7'];
        if ($name === 'hcaptcha') {
            $expected['sitekey'] = 'site-key';   // so a token from another site is refused by hCaptcha
        }
        ksort($expected);
        ksort($sent);
        $this->assertSame($expected, $sent);
    }

    public function testTheAnswerIsRead(): void
    {
        $client = new FakeClient([
            '{"success": true, "score": 0.7, "action": "checkout", "hostname": "www.example.com"}',
            '{"success": false, "error-codes": ["timeout-or-duplicate"]}',
            '{"success": true, "score": 7}',
        ]);
        $verifier = self::provider('recaptcha_v3', $client);

        $human = $verifier->verify('t');
        $this->assertSame([true, 0.7, 'checkout', 'www.example.com'], [$human->human, $human->score, $human->action, $human->hostname]);
        $bot = $verifier->verify('t');
        $this->assertSame([false, false, ['timeout-or-duplicate']], [$bot->human, $bot->unavailable, $bot->errors]);
        $this->assertSame(1.0, $verifier->verify('t')->score, 'a score is kept between 0 and 1');
        $this->assertTrue($verifier->scores());
        $this->assertFalse(self::provider('turnstile', $client)->scores());
    }

    /**
     * @return iterable<string, array{0: ResponseInterface|\Throwable|string|null, 1: string}>
     */
    public static function unavailable(): iterable
    {
        yield 'a wrong secret' => ['{"success": false, "error-codes": ["invalid-input-secret"]}', 'invalid-input-secret'];
        yield 'no secret' => ['{"success": false, "error-codes": ["missing-input-secret"]}', 'missing-input-secret'];
        yield 'a server error' => [new Response(500), 'http-500'];
        yield 'not JSON' => ['<html>busy</html>', 'unreadable-answer'];
        yield 'no success' => ['{"ok": true}', 'unreadable-answer'];
        yield 'success as text' => ['{"success": "true"}', 'unreadable-answer'];
        yield 'deep JSON' => [str_repeat('[', 50) . str_repeat(']', 50), 'unreadable-answer'];
        yield 'the network' => [new \RuntimeException('Connection timed out'), 'http-client-error'];
        yield 'no client' => [null, 'no-http-client'];
    }

    /**
     * A provider that cannot be asked, or says the application's secret is
     * wrong, is unavailable: refused by default, and never taken for the
     * visitor being a bot.
     */
    #[DataProvider('unavailable')]
    public function testWhatIsNotTheVisitorsFaultIsUnavailable(ResponseInterface|\Throwable|string|null $answer, string $why): void
    {
        $verifier = self::provider('turnstile', $answer === null ? null : new FakeClient([$answer]));

        $verdict = $verifier->verify('t', '198.51.100.7');

        $this->assertSame([false, true, [$why]], [$verdict->human, $verdict->unavailable, $verdict->errors]);
    }

    // ── The widget ─────────────────────────────────────────────────────────

    public function testTheWidgetEscapesWhatItPrints(): void
    {
        $verifier = Providers::create('turnstile', 's', 'key"><script>alert(1)</script>', null, new Psr17Factory(), new Psr17Factory());

        $html = $verifier->widget('contact"><b>', 'n0nce"x');

        $this->assertStringContainsString('<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer nonce="n0nce&quot;x"></script>', $html);
        $this->assertStringContainsString('data-sitekey="key&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"', $html);
        $this->assertStringContainsString('data-action="contact&quot;&gt;&lt;b&gt;"', $html);
        $this->assertStringNotContainsString('<script>alert', $html);
    }

    public function testReCaptchaV3AsksForATokenWhenTheFormIsSent(): void
    {
        $html = Providers::create('recaptcha_v3', 's', 'site-key', null, new Psr17Factory(), new Psr17Factory())->widget('checkout</script><script>x', 'abc');

        $this->assertStringContainsString('src="https://www.google.com/recaptcha/api.js?render=site-key"', $html);
        $this->assertStringContainsString('<input type="hidden" name="g-recaptcha-response"', $html);
        $this->assertStringContainsString('<script nonce="abc">', $html, 'the inline script carries the nonce');
        $this->assertSame(2, substr_count($html, '</script>'), 'the action cannot close the script: only the two scripts end');
        $this->assertStringContainsString(substr((string) json_encode('checkout</script><script>x', JSON_HEX_TAG), 1, -1), $html, 'the action is encoded, so it cannot close the script');
        $this->assertStringContainsString('grecaptcha.execute(s.key,{action:s.action})', $html);
    }

    public function testEachWidget(): void
    {
        $widget = static fn (string $name): string => Providers::create($name, 's', 'k', null, new Psr17Factory(), new Psr17Factory())->widget();

        $this->assertStringContainsString('<div class="cf-turnstile" data-sitekey="k"></div>', $widget('turnstile'));
        $this->assertStringContainsString('<div class="g-recaptcha" data-sitekey="k"></div>', $widget('recaptcha_v2'));
        $this->assertStringContainsString('<div class="h-captcha" data-sitekey="k"></div>', $widget('hcaptcha'));
        $this->assertStringNotContainsString('nonce', $widget('turnstile'), 'no nonce without one');
    }

    // ── Configuration ──────────────────────────────────────────────────────

    public function testTheProviderIsChosenByConfiguration(): void
    {
        foreach (Providers::ALL as $name => $class) {
            $verifier = $this->app(['captcha.provider' => $name, 'captcha.secret' => 's', 'captcha.site_key' => 'k'], new FakeClient([]))->container()->get(BotVerifierInterface::class);
            $this->assertInstanceOf($class, $verifier, $name);
        }

        $unset = $this->app([])->container()->get(BotVerifierInterface::class);
        $this->assertInstanceOf(Unconfigured::class, $unset);
        $this->assertSame(['captcha-provider-not-set'], $unset->verify('t')->errors);
        $this->assertTrue($unset->verify('t')->unavailable, 'refused, never let through');
        $this->assertSame(['captcha-provider-unknown'], $this->app(['captcha.provider' => 'akismet'])->container()->get(BotVerifierInterface::class)->verify('t')->errors);
    }

    public function testTheWidgetHelper(): void
    {
        $helpers = $this->app(['captcha.provider' => 'hcaptcha', 'captcha.secret' => 's', 'captcha.site_key' => 'k'], new FakeClient([]))->container()->get(ViewHelpers::class);
        assert($helpers instanceof ViewHelpers);

        $this->assertTrue($helpers->isSafe('captcha_widget'));
        $this->assertStringContainsString('<script src="https://js.hcaptcha.com/1/api.js" async defer nonce="n1"></script><div class="h-captcha" data-sitekey="k"></div>', (string) $helpers->call('captcha_widget', ['contact', 'n1']));

        $none = $this->app([])->container()->get(ViewHelpers::class);
        assert($none instanceof ViewHelpers);
        $this->assertSame('', (string) $none->call('captcha_widget', []), 'nothing until a provider is named');
    }

    public function testThroughTheMiddleware(): void
    {
        $client = new FakeClient(['{"success": true, "action": "contact"}', '{"success": true, "action": "login"}']);
        $verifier = Providers::create('turnstile', 's', 'k', $client, new Psr17Factory(), new Psr17Factory());
        $middleware = new BotVerificationMiddleware($verifier);
        $post = (new ServerRequest('POST', '/contact', serverParams: ['REMOTE_ADDR' => '198.51.100.7']))
            ->withParsedBody(['cf-turnstile-response' => 'tok'])
            ->withAttribute('_handler', [ContactForm::class, 'send']);

        $this->assertSame(200, $middleware->process($post, new Ok())->getStatusCode());
        $this->expectException(ForbiddenHttpException::class);   // a token made for the login form
        $middleware->process($post, new Ok());
    }

    // ── check ──────────────────────────────────────────────────────────────

    public function testCheckSaysWhatWouldRefuseEveryVisitor(): void
    {
        $guarded = static fn (Router $r) => $r->post('/contact', [ContactForm::class, 'send'])->middleware(BotVerificationMiddleware::class);

        $this->assertSame([], $this->check([]), 'not in use');
        $this->assertSame(["Error captcha.provider is not set, so the bot verifier asks nobody and every request to POST /contact is refused."], self::lines($this->check([], routes: $guarded)));
        $this->assertSame(['Error captcha.provider is "akismet", not one of turnstile, recaptcha_v2, recaptcha_v3, hcaptcha.'], self::lines($this->check(['captcha.provider' => 'akismet'])));
        $this->assertSame([
            'Error captcha.secret is not set, so the provider cannot be asked and every protected form is refused.',
            'Error captcha.site_key is not set, so the provider cannot be asked and every protected form is refused.',
            'Error No PSR-18 HTTP client (Psr\Http\Client\ClientInterface) is registered, so the provider cannot be asked and every protected form is refused.',
        ], self::lines($this->check(['captcha.provider' => 'turnstile'], client: false)));
        $this->assertSame([], $this->check(self::configured()));
        $this->assertSame(Severity::Warning, $this->check(['captcha.provider' => 'turnstile'], strict: false)[0]->severity, 'a warning unless strict');
    }

    public function testCheckSaysWhenThePolicyBlocksTheWidget(): void
    {
        $headers = ['http.middleware' => [SecurityHeadersMiddleware::class]];

        $blocked = $this->check([...self::configured(), ...$headers]);   // the default policy: default-src 'self'
        $this->assertSame(['captcha.csp'], array_map(static fn (Finding $f): string => $f->id, $blocked));
        $this->assertSame(Severity::Error, $blocked[0]->severity);
        $this->assertStringContainsString('blocks the turnstile widget (script-src https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com)', $blocked[0]->message);

        $allowed = ['script-src' => ["'self'", 'https://challenges.cloudflare.com'], 'frame-src' => ['challenges.cloudflare.com']];
        $this->assertSame([], $this->check([...self::configured(), ...$headers, 'http.security_headers' => ['csp' => $allowed]]), 'by origin or by host');
        $this->assertSame([], $this->check([...self::configured(), ...$headers, 'http.security_headers' => ['csp' => ['script-src' => ["'strict-dynamic'", '{nonce}'], 'frame-src' => ['https:']]]]), 'a nonce with strict-dynamic, and a scheme');
        $this->assertSame([], $this->check([...self::configured(), ...$headers, 'http.security_headers' => ['csp' => ['default-src' => null]]]), 'no default-src: frames and scripts unrestricted');

        $wildcards = static fn (string $host): array => ['script-src' => [$host], 'frame-src' => [$host]];
        $this->assertSame([], $this->check([...self::configured(), ...$headers, 'http.security_headers' => ['csp' => $wildcards('https://*.cloudflare.com')]]), 'a wildcard over the provider');
        $this->assertCount(1, $this->check([...self::configured(), ...$headers, 'http.security_headers' => ['csp' => $wildcards('https://*.example.com')]]), 'a wildcard over another domain allows nothing of it');
        $this->assertCount(1, $this->check([...self::configured(), ...$headers, 'http.security_headers' => ['csp' => $wildcards('*.flare.com')]]), 'nor one that only ends like it');

        $partly = $this->check([...self::configured(), ...$headers, 'http.security_headers' => ['csp' => ['script-src' => ['https://challenges.cloudflare.com']]]]);
        $this->assertStringContainsString('(frame-src https://challenges.cloudflare.com)', $partly[0]->message, 'frames fall back to default-src');

        $report = $this->check([...self::configured(), ...$headers, 'http.security_headers' => ['csp_report_only' => true]]);
        $this->assertSame(Severity::Warning, $report[0]->severity);
        $this->assertStringContainsString('report-only for now', $report[0]->message);
    }

    public function testReCaptchaV3NeedsTheNonceForItsInlineScript(): void
    {
        $config = ['captcha.provider' => 'recaptcha_v3', 'captcha.secret' => 's', 'captcha.site_key' => 'k', 'http.middleware' => [SecurityHeadersMiddleware::class]];
        $hosts = ['script-src' => ["'self'", 'https://www.google.com', 'https://www.gstatic.com'], 'frame-src' => ['https://www.google.com']];

        $noNonce = $this->check([...$config, 'http.security_headers' => ['csp' => $hosts]]);   // as on a site whose page cache rules out nonces
        $this->assertCount(1, $noNonce);
        $this->assertStringContainsString('(script-src {nonce})', $noNonce[0]->message);
        $this->assertSame([], $this->check([...$config, 'http.security_headers' => ['csp' => [...$hosts, 'script-src' => [...$hosts['script-src'], '{nonce}']]]]));
        $this->assertSame([], $this->check([...$config, 'http.security_headers' => ['csp' => [...$hosts, 'script-src' => [...$hosts['script-src'], "'unsafe-inline'"]]]]));
        $this->assertSame([], $this->check(['captcha.provider' => 'turnstile', 'captcha.secret' => 's', 'captcha.site_key' => 'k', 'http.middleware' => [SecurityHeadersMiddleware::class], 'http.security_headers' => ['csp' => ['script-src' => ["'self'", 'https://challenges.cloudflare.com'], 'frame-src' => ['https://challenges.cloudflare.com']]]]), 'Turnstile needs no nonce');
    }

    public function testHCaptchasWildcardHosts(): void
    {
        $config = ['captcha.provider' => 'hcaptcha', 'captcha.secret' => 's', 'captcha.site_key' => 'k', 'http.middleware' => [SecurityHeadersMiddleware::class]];
        $hosts = ['https://hcaptcha.com', 'https://*.hcaptcha.com'];
        $all = ['script-src' => $hosts, 'frame-src' => $hosts, 'style-src' => [...$hosts, "'self'"], 'connect-src' => ['hcaptcha.com', '*.hcaptcha.com']];

        $this->assertSame([], $this->check([...$config, 'http.security_headers' => ['csp' => $all]]));
        $narrow = $this->check([...$config, 'http.security_headers' => ['csp' => [...$all, 'frame-src' => ['https://newassets.hcaptcha.com']]]]);
        $this->assertStringContainsString('frame-src https://hcaptcha.com https://*.hcaptcha.com', $narrow[0]->message, 'one subdomain is not the wildcard');
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /**
     * @return array<string, string>
     */
    private static function configured(): array
    {
        return ['captcha.provider' => 'turnstile', 'captcha.secret' => 's', 'captcha.site_key' => 'k'];
    }

    private static function provider(string $name, ?ClientInterface $client): SiteVerify
    {
        return Providers::create($name, 's3cret', 'site-key', $client, new Psr17Factory(), new Psr17Factory());
    }

    /**
     * @param array<string, mixed> $config
     */
    private function app(array $config, ?ClientInterface $client = null): ApplicationInterface
    {
        return Application::configure(sys_get_temp_dir() . '/zana-captcha')
            ->withEnvironment('testing')
            ->withConfiguration(['security.secret' => str_repeat('s', 40), 'app.debug' => false, ...$config])
            ->withProviders(HttpServiceProvider::class, RoutingServiceProvider::class, SecurityServiceProvider::class, ViewServiceProvider::class, CaptchaServiceProvider::class)
            ->withServices(static function (ServiceCollectionInterface $s) use ($client): void {
                if ($client !== null) {
                    $s->singleton(ClientInterface::class, static fn (): ClientInterface => $client);
                }
            })
            ->build();
    }

    /**
     * @param array<string, mixed> $config
     * @return list<Finding>
     */
    private function check(array $config, ?\Closure $routes = null, bool $client = true, bool $strict = true): array
    {
        $app = $this->app(['security.strict' => $strict, ...$config], $client ? new FakeClient([]) : null);
        if ($routes !== null) {
            $router = $app->container()->get(Router::class);
            assert($router instanceof Router);
            $routes($router);
        }
        foreach ($app->container()->tagged(ApplicationCheck::TAG) as $check) {
            if ($check instanceof CaptchaCheck) {
                return $check->findings($app);
            }
        }
        self::fail('CaptchaCheck is not tagged.');
    }

    /**
     * @param list<Finding> $findings
     * @return list<string>
     */
    private static function lines(array $findings): array
    {
        return array_map(static fn (Finding $f): string => "{$f->severity->name} {$f->message}", $findings);
    }
}

/** A PSR-18 client that never touches the network: it answers from a list, and records each request. */
final class FakeClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];

    /**
     * @param list<ResponseInterface|\Throwable|string> $answers JSON bodies, responses or errors, in order
     */
    public function __construct(private array $answers)
    {
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;
        $answer = array_shift($this->answers) ?? throw new \LogicException('No answer left for ' . $request->getUri());

        return match (true) {
            $answer instanceof \Throwable => throw $answer,
            $answer instanceof ResponseInterface => $answer,
            default => new Response(200, ['Content-Type' => 'application/json'], $answer),
        };
    }
}

#[PublicRoute(reason: 'The contact form')]
final class ContactForm
{
    #[VerifyHuman(action: 'contact')]
    public function send(): string
    {
        return 'sent';
    }
}

final class Ok implements RequestHandlerInterface
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return new Response(200);
    }
}
