<?php

declare(strict_types=1);

namespace Zana\Captcha;

use Psr\Http\Client\ClientInterface;
use Zana\Configuration\ConfigurationInterface;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\SecurityRules;
use Zana\Core\Inspection\Severity;
use Zana\Http\SecurityHeadersMiddleware;
use Zana\Routing\Router;
use Zana\Security\Attribute\VerifyHuman;

/**
 * captcha.* (2.25, FE-64): settings that would make the widget fail, which
 * would refuse every visitor, since a form without a token is refused.
 * Errors with security.strict, warnings otherwise:
 *
 * - captcha.config: captcha.provider names no provider, or the secret or
 *   site key is missing;
 * - captcha.http_client: no PSR-18 client is registered to ask the provider;
 * - captcha.csp: the Content-Security-Policy that SecurityHeadersMiddleware
 *   sends blocks the provider's script or frame (a report-only policy is a
 *   warning).
 */
final readonly class CaptchaCheck implements ApplicationCheck
{
    public function findings(ApplicationInterface $application): array
    {
        $container = $application->container();
        $config = $container->get(ConfigurationInterface::class);
        assert($config instanceof ConfigurationInterface);
        $provider = $config->get('captcha.provider');
        $strict = SecurityRules::severity($application);
        if ($provider === null) {
            $guarded = self::guardedRoutes($application);

            return $guarded === [] ? [] : [new Finding(
                'captcha.config',
                $strict,
                'captcha.provider is not set, so the bot verifier asks nobody and every request to ' . implode(', ', array_slice($guarded, 0, 3)) . (count($guarded) > 3 ? ', …' : '') . ' is refused.',
                hint: "Set it in config/captcha.php, e.g. 'provider' => 'turnstile', with captcha.secret and captcha.site_key from the environment.",
                security: true,
            )];
        }
        if (!is_string($provider) || !isset(Providers::ALL[$provider])) {
            return [new Finding('captcha.config', $strict, 'captcha.provider is ' . json_encode($provider) . ', not one of ' . implode(', ', array_keys(Providers::ALL)) . '.', hint: "Set it in config/captcha.php, e.g. 'provider' => 'turnstile'.", security: true)];
        }

        $findings = [];
        foreach (['secret' => 'APP_CAPTCHA__SECRET', 'site_key' => 'APP_CAPTCHA__SITE_KEY'] as $key => $variable) {
            $value = $config->get("captcha.{$key}");
            if (!is_string($value) || trim($value) === '') {
                $findings[] = new Finding('captcha.config', $strict, "captcha.{$key} is not set, so the provider cannot be asked and every protected form is refused.", hint: "Set it from the environment, {$variable}, with the value from the provider's dashboard.", security: true);
            }
        }
        if (!$container->has(ClientInterface::class)) {
            $findings[] = new Finding(
                'captcha.http_client',
                $strict,
                'No PSR-18 HTTP client (' . ClientInterface::class . ') is registered, so the provider cannot be asked and every protected form is refused.',
                hint: 'Install one, e.g. composer require symfony/http-client nyholm/psr7, and register it: $services->singleton(ClientInterface::class, fn () => new Psr18Client());',
                security: true,
            );
        }

        $policy = self::policy($config);
        if ($policy !== null) {
            $verifier = Providers::create($provider, 'x', 'x', null, new \Nyholm\Psr7\Factory\Psr17Factory(), new \Nyholm\Psr7\Factory\Psr17Factory());
            $refused = ContentSecurityPolicy::refused($policy->directives(), $verifier->cspSources());
            if ($refused !== []) {
                $list = implode('; ', array_map(static fn (string $directive, array $sources): string => $directive . ' ' . implode(' ', $sources), array_keys($refused), $refused));
                $findings[] = new Finding(
                    'captcha.csp',
                    $policy->reportOnly() ? Severity::Warning : $strict,
                    "The Content-Security-Policy blocks the {$provider} widget ({$list}), so no visitor can get a token, and every protected form is refused."
                        . ($policy->reportOnly() ? ' The policy is report-only for now.' : ''),
                    hint: "Add to http.security_headers.csp: {$list}.",
                    security: true,
                );
            }
        }

        return $findings;
    }

    /**
     * The routes whose handler has #[VerifyHuman], as "METHODS /path".
     *
     * @return list<string>
     */
    private static function guardedRoutes(ApplicationInterface $application): array
    {
        $container = $application->container();
        if (!class_exists(Router::class) || !$container->has(Router::class)) {
            return [];
        }
        $router = $container->get(Router::class);
        assert($router instanceof Router);
        $guarded = [];
        foreach ($router->routes() as $route) {
            $handler = $route->handler;
            $targets = match (true) {
                $handler instanceof \Closure => [new \ReflectionFunction($handler)],
                is_string($handler) && class_exists($handler) => [new \ReflectionClass($handler), ...(method_exists($handler, '__invoke') ? [new \ReflectionMethod($handler, '__invoke')] : [])],
                is_array($handler) && class_exists($handler[0]) => [new \ReflectionClass($handler[0]), ...(method_exists($handler[0], $handler[1]) ? [new \ReflectionMethod($handler[0], $handler[1])] : [])],
                default => [],
            };
            foreach ($targets as $target) {
                if ($target->getAttributes(VerifyHuman::class) !== []) {
                    $guarded[] = implode('|', $route->methods) . ' ' . $route->path;
                    break;
                }
            }
        }

        return $guarded;
    }

    private static function policy(ConfigurationInterface $config): ?SecurityHeadersMiddleware
    {
        foreach ($config->array('http.middleware', []) as $middleware) {
            if (is_string($middleware) && is_a($middleware, SecurityHeadersMiddleware::class, true)) {
                return SecurityHeadersMiddleware::fromConfig($config->array('http.security_headers', []));
            }
        }

        return null;
    }
}
