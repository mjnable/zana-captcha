<?php

declare(strict_types=1);

namespace Zana\Captcha\Tests;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use Zana\Http\Exception\ForbiddenHttpException;
use Zana\Security\Middleware\BotVerificationMiddleware;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\Psr18Client;
use Zana\Captcha\Provider\HCaptcha;
use Zana\Captcha\Provider\ReCaptchaV2;
use Zana\Captcha\Provider\ReCaptchaV3;
use Zana\Captcha\Provider\SiteVerify;
use Zana\Captcha\Provider\Turnstile;
use Zana\Security\Bot\BotVerdict;

/**
 * The providers' real siteverify endpoints, with the test keys each one publishes (2.30), through the HTTP client the
 * README documents. Opt-in, as it needs the network: ZANA_TEST_CAPTCHA_LIVE=1 vendor/bin/phpunit --filter Live.
 *
 * What each provider answers, as found on 2026-11-21, is written down here, so a change on their side shows:
 *
 * - Turnstile: secret 1x… passes the dummy token, 2x… fails it, 3x… says it was spent; a wrong secret is named as
 *   one. The answer names the hostname "example.com", and no action.
 * - reCAPTCHA: the v2 test secret passes any token, naming "testkey.google.com", with no score. A wrong or empty
 *   secret is answered as a wrong token (invalid-input-response), never as a wrong secret: Zana cannot tell them
 *   apart, so it refuses, as for a bot.
 * - hCaptcha: the test secret passes the test token, naming "dummy-key-pass", also when sent twice; another token
 *   fails.
 *
 * @see https://developers.cloudflare.com/turnstile/troubleshooting/testing/
 * @see https://developers.google.com/recaptcha/docs/faq
 * @see https://docs.hcaptcha.com
 */
final class LiveProvidersTest extends TestCase
{
    private const string TURNSTILE_SITE = '1x00000000000000000000AA';

    private const string TURNSTILE_TOKEN = 'XXXX.DUMMY.TOKEN.XXXX';

    private const string RECAPTCHA_SITE = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';

    private const string RECAPTCHA_SECRET = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

    private const string HCAPTCHA_SITE = '10000000-ffff-ffff-ffff-000000000001';

    private const string HCAPTCHA_SECRET = '0x0000000000000000000000000000000000000000';

    private const string HCAPTCHA_TOKEN = '10000000-aaaa-bbbb-cccc-000000000001';

    protected function setUp(): void
    {
        if (getenv('ZANA_TEST_CAPTCHA_LIVE') !== '1') {
            self::markTestSkipped('The providers\' real endpoints: set ZANA_TEST_CAPTCHA_LIVE=1 to ask them.');
        }
    }

    public function testTurnstile(): void
    {
        $human = $this->ask(new Turnstile('1x0000000000000000000000000000000AA', self::TURNSTILE_SITE, ...$this->http()), self::TURNSTILE_TOKEN);
        $this->assertTrue($human->human);
        $this->assertSame('example.com', $human->hostname, 'the test keys name this host: an expected hostname refuses them');
        $this->assertNull($human->action, 'and no action: an expected action refuses them too');

        $bot = $this->ask(new Turnstile('2x0000000000000000000000000000000AA', self::TURNSTILE_SITE, ...$this->http()), self::TURNSTILE_TOKEN);
        $this->assertFalse($bot->human || $bot->unavailable || $bot->misconfigured);
        $this->assertSame(['invalid-input-response'], $bot->errors);

        $spent = $this->ask(new Turnstile('3x0000000000000000000000000000000AA', self::TURNSTILE_SITE, ...$this->http()), self::TURNSTILE_TOKEN);
        $this->assertFalse($spent->human);
        $this->assertSame(['timeout-or-duplicate'], $spent->errors);

        $wrong = $this->ask(new Turnstile('not-a-secret', self::TURNSTILE_SITE, ...$this->http()), self::TURNSTILE_TOKEN);
        $this->assertTrue($wrong->misconfigured, 'a wrong secret is the application\'s mistake, named as one');
    }

    /**
     * Cloudflare answers a wrong or missing secret with HTTP 400, and the error in the body. Before 2.30, any answer
     * but 200 counted as the provider out of reach, so with on_unavailable "allow", a wrong secret let every request
     * through.
     */
    public function testAWrongTurnstileSecretIsRefusedEvenWhenOutagesAreAllowed(): void
    {
        foreach (['not-a-secret', ''] as $secret) {
            $middleware = new BotVerificationMiddleware(new Turnstile($secret, self::TURNSTILE_SITE, ...$this->http()), onUnavailable: 'allow');
            $post = (new ServerRequest('POST', '/contact', serverParams: ['REMOTE_ADDR' => '203.0.113.9']))
                ->withParsedBody(['cf-turnstile-response' => self::TURNSTILE_TOKEN])
                ->withAttribute('_handler', [ContactForm::class, 'send']);
            try {
                $middleware->process($post, new Ok());
                $this->fail("Let through with the secret [{$secret}].");
            } catch (ForbiddenHttpException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testRecaptcha(): void
    {
        $human = $this->ask(new ReCaptchaV2(self::RECAPTCHA_SECRET, self::RECAPTCHA_SITE, ...$this->http()), 'any token at all');
        $this->assertTrue($human->human);
        $this->assertSame('testkey.google.com', $human->hostname);

        $v3 = $this->ask(new ReCaptchaV3(self::RECAPTCHA_SECRET, self::RECAPTCHA_SITE, ...$this->http()), 'any token at all');
        $this->assertTrue($v3->human);
        $this->assertNull($v3->score, 'v2\'s test keys give v3 no score: Google asks for a key of its own to test v3');

        // Google answers a wrong or empty secret as a wrong token, so Zana refuses it as it refuses a bot, and cannot
        // log it as the application's mistake.
        foreach (['', 'wrong', substr(self::RECAPTCHA_SECRET, 0, -1) . 'X'] as $secret) {
            $wrong = $this->ask(new ReCaptchaV2($secret, self::RECAPTCHA_SITE, ...$this->http()), 'any token at all');
            $this->assertFalse($wrong->human, "secret [{$secret}]: refused");
            $this->assertSame(['invalid-input-response'], $wrong->errors, "secret [{$secret}]");
            $this->assertFalse($wrong->misconfigured, 'as Google answers it');
        }
    }

    public function testHcaptcha(): void
    {
        $verifier = new HCaptcha(self::HCAPTCHA_SECRET, self::HCAPTCHA_SITE, ...$this->http());

        $human = $this->ask($verifier, self::HCAPTCHA_TOKEN);
        $this->assertTrue($human->human);
        $this->assertSame('dummy-key-pass', $human->hostname);
        $this->assertTrue($this->ask($verifier, self::HCAPTCHA_TOKEN)->human, 'the test token passes again');

        $bot = $this->ask($verifier, 'not-the-test-token');
        $this->assertFalse($bot->human || $bot->unavailable || $bot->misconfigured);
        $this->assertSame(['invalid-input-response'], $bot->errors);
    }

    private function ask(SiteVerify $verifier, string $token): BotVerdict
    {
        $started = microtime(true);
        $verdict = $verifier->verify($token, '203.0.113.9');
        $this->assertLessThan(5.0, microtime(true) - $started, 'within the client\'s bound');
        $this->assertFalse($verdict->unavailable && !$verdict->misconfigured, $verifier::class . ' could not be asked: ' . implode(', ', $verdict->errors));

        return $verdict;
    }

    /**
     * The client the README documents: bounded, and no retries.
     *
     * @return array{Psr18Client, Psr17Factory, Psr17Factory}
     */
    private function http(): array
    {
        $factory = new Psr17Factory();

        return [new Psr18Client(HttpClient::create(['max_connect_duration' => 2, 'timeout' => 3, 'max_duration' => 5]), $factory, $factory), $factory, $factory];   // the client, then the factories the verifier uses
    }
}
