<?php

declare(strict_types=1);

namespace Zana\Captcha\Provider;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Zana\Security\Bot\BotVerdict;
use Zana\Security\Bot\BotVerifierInterface;

/**
 * What Cloudflare Turnstile, Google reCAPTCHA and hCaptcha share (2.25,
 * FE-64): one HTTPS POST of the secret, the token and the client address to
 * the provider's siteverify endpoint, through the application's PSR-18
 * client, and a JSON answer with "success", and for some a score, the
 * action and the hostname.
 *
 * The answer is unavailable, not a bot, when the provider cannot be asked
 * or its answer cannot be read, and when it says the secret is missing or
 * wrong: that is the application's mistake, not the visitor's.
 */
abstract class SiteVerify implements BotVerifierInterface
{
    /** Codes that mean the application, not the visitor, is wrong. */
    private const array OWN_MISTAKES = ['missing-input-secret', 'invalid-input-secret', 'sitekey-secret-mismatch', 'invalid-or-already-seen-response-secret'];

    public function __construct(
        protected readonly string $secret,
        protected readonly string $siteKey,
        private readonly ?ClientInterface $client,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
    ) {
    }

    /** The provider's siteverify URL. */
    abstract public function endpoint(): string;

    /** The script the widget needs. */
    abstract public function script(): string;

    /**
     * The widget's HTML, after the script tag.
     */
    abstract protected function element(?string $action, ?string $nonce): string;

    /**
     * The sources the provider needs in a Content-Security-Policy, by
     * directive.
     *
     * @return array<string, list<string>>
     */
    abstract public function cspSources(): array;

    public function scores(): bool
    {
        return false;
    }

    /**
     * The script and the widget, for a template:
     * `<?= $this->captcha_widget('contact', $csp_nonce) ?>`.
     */
    public function widget(?string $action = null, ?string $nonce = null): string
    {
        $nonceAttribute = $nonce === null ? '' : ' nonce="' . self::e($nonce) . '"';

        return '<script src="' . self::e($this->script()) . '" async defer' . $nonceAttribute . '></script>' . $this->element($action, $nonce);
    }

    public function verify(string $token, ?string $clientIp = null, ?string $action = null): BotVerdict
    {
        if ($this->client === null) {
            return BotVerdict::unavailable('no-http-client');
        }
        $fields = ['secret' => $this->secret, 'response' => $token, ...$this->extraFields()];
        if ($clientIp !== null) {
            $fields['remoteip'] = $clientIp;
        }
        $request = $this->requests->createRequest('POST', $this->endpoint())
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streams->createStream(http_build_query($fields)));

        try {
            $response = $this->client->sendRequest($request);
        } catch (\Throwable $e) {
            return BotVerdict::unavailable('http-client-error');
        }
        if ($response->getStatusCode() !== 200) {
            return BotVerdict::unavailable('http-' . $response->getStatusCode());
        }
        $answer = json_decode((string) $response->getBody(), true, 8);
        if (!is_array($answer) || !is_bool($answer['success'] ?? null)) {
            return BotVerdict::unavailable('unreadable-answer');
        }

        $codes = array_values(array_filter(is_array($answer['error-codes'] ?? null) ? $answer['error-codes'] : [], is_string(...)));
        if (array_intersect($codes, self::OWN_MISTAKES) !== []) {
            return BotVerdict::unavailable(implode(',', array_intersect($codes, self::OWN_MISTAKES)));
        }
        if (!$answer['success']) {
            return BotVerdict::bot($codes, self::score($answer));
        }

        return BotVerdict::human(
            self::score($answer),
            is_string($answer['action'] ?? null) && $answer['action'] !== '' ? $answer['action'] : null,
            is_string($answer['hostname'] ?? null) && $answer['hostname'] !== '' ? $answer['hostname'] : null,
        );
    }

    /**
     * More fields for the provider, such as hCaptcha's "sitekey".
     *
     * @return array<string, string>
     */
    protected function extraFields(): array
    {
        return [];
    }

    protected static function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * @param array<mixed> $answer
     */
    private static function score(array $answer): ?float
    {
        $score = $answer['score'] ?? null;

        return is_int($score) || is_float($score) ? max(0.0, min(1.0, (float) $score)) : null;
    }
}
