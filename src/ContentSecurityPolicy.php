<?php

declare(strict_types=1);

namespace Zana\Captcha;

/**
 * Whether a Content-Security-Policy lets a page load a source (2.25), as a
 * browser decides it for the directives a CAPTCHA widget needs: a directive
 * falls back to child-src (frames) and default-src when absent; a source
 * matches as "*", its scheme ("https:"), its origin, its host, or a
 * "*.domain" wildcard, and since 2.25.1 a path ("https://www.google.com/recaptcha/",
 * as Google documents it); and a script-src with 'strict-dynamic' lets a
 * script carrying the nonce load the rest.
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
        [$host, $path] = self::split($source);
        foreach ($allowed as $entry) {
            $entry = strtolower($entry);
            if ($entry === '*' || $entry === 'https:') {
                return true;
            }
            if (str_starts_with($entry, "'") || (str_contains($entry, '://') && !str_starts_with($entry, 'https://'))) {
                continue;   // a keyword, or another scheme
            }
            [$entryHost, $entryPath] = self::split($entry);
            if (!self::hostMatches($entryHost, $host) || !self::pathMatches($entryPath, $path)) {
                continue;
            }

            return true;
        }

        return false;
    }

    /**
     * A source's host and path, lower case: "https://www.google.com/recaptcha/"
     * gives ["www.google.com", "/recaptcha/"]; a bare host gives an empty path.
     *
     * @return array{0: string, 1: string}
     */
    private static function split(string $source): array
    {
        $rest = strtolower((string) preg_replace('#^https://#i', '', $source));
        $slash = strpos($rest, '/');

        return $slash === false ? [$rest, ''] : [substr($rest, 0, $slash), substr($rest, $slash)];
    }

    /**
     * "*.example.com" covers sub.example.com, not example.com; a needed
     * wildcard is covered only by the same wildcard.
     */
    private static function hostMatches(string $entry, string $needed): bool
    {
        if ($entry === $needed) {
            return true;
        }

        return str_starts_with($entry, '*.') && !str_starts_with($needed, '*.') && str_ends_with($needed, substr($entry, 1));
    }

    /**
     * As CSP decides (2.25.1): an entry without a path, or "/", covers every
     * path; one ending in "/" covers what lies under it; any other only that
     * exact path. What the widget needs at the root of a host is covered only
     * by an entry that covers the root.
     */
    private static function pathMatches(string $entry, string $needed): bool
    {
        if ($entry === '' || $entry === '/') {
            return true;
        }
        if ($needed === '') {
            return false;
        }

        return str_ends_with($entry, '/') ? str_starts_with($needed, $entry) : $entry === $needed;
    }
}
