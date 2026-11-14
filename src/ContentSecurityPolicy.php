<?php

declare(strict_types=1);

namespace Zana\Captcha;

/**
 * Whether a Content-Security-Policy lets a page load a source (2.25), as a
 * browser decides it for the directives a CAPTCHA widget needs: a directive
 * falls back to child-src (frames) and default-src when absent; a source
 * matches as "*", its scheme ("https:"), its origin, its host, or a
 * "*.domain" wildcard; and a script-src with 'strict-dynamic' lets a script
 * carrying the nonce load the rest.
 *
 * @internal
 */
final class ContentSecurityPolicy
{
    /**
     * The sources a policy refuses, by directive.
     *
     * @param array<string, list<string>> $policy As SecurityHeadersMiddleware::directives() gives it
     * @param array<string, list<string>> $needed As SiteVerify::cspSources() gives it
     * @return array<string, list<string>>
     */
    public static function refused(array $policy, array $needed): array
    {
        $refused = [];
        foreach ($needed as $directive => $sources) {
            $allowed = self::effective($policy, $directive);
            if ($allowed === null) {
                continue;   // no such directive and no default-src: nothing is restricted
            }
            if ($directive === 'script-src' && in_array("'strict-dynamic'", $allowed, true) && in_array('{nonce}', $allowed, true)) {
                continue;   // the widget's script carries the nonce, and may load the rest
            }
            foreach ($sources as $source) {
                if (!self::allows($allowed, $source)) {
                    $refused[$directive][] = $source;
                }
            }
        }

        return $refused;
    }

    /**
     * @param array<string, list<string>> $policy
     * @return list<string>|null
     */
    private static function effective(array $policy, string $directive): ?array
    {
        $chain = match ($directive) {
            'frame-src' => ['frame-src', 'child-src', 'default-src'],
            default => [$directive, 'default-src'],
        };
        foreach ($chain as $name) {
            if (isset($policy[$name])) {
                return $policy[$name];
            }
        }

        return null;
    }

    /**
     * @param list<string> $allowed
     */
    private static function allows(array $allowed, string $source): bool
    {
        if ($source === '{nonce}') {   // an inline script: allowed by the nonce, or by 'unsafe-inline'
            return in_array('{nonce}', $allowed, true) || in_array("'unsafe-inline'", $allowed, true);
        }
        $host = strtolower((string) parse_url(str_replace('*.', 'wildcard.', $source), PHP_URL_HOST));
        $host = str_replace('wildcard.', '*.', $host);
        foreach ($allowed as $entry) {
            $entry = strtolower(rtrim($entry, '/'));
            if ($entry === '*' || $entry === 'https:' || $entry === strtolower($source) || $entry === $host || $entry === "https://{$host}") {
                return true;
            }
            $bare = preg_replace('#^https://#', '', $entry);
            if (is_string($bare) && str_starts_with($bare, '*.') && !str_starts_with($host, '*.') && str_ends_with($host, substr($bare, 1))) {
                return true;   // *.example.com allows sub.example.com
            }
        }

        return false;
    }
}
