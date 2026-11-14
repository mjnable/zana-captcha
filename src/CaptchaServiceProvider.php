<?php

declare(strict_types=1);

namespace Zana\Captcha;

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Client\ClientInterface;
use Zana\Captcha\Provider\SiteVerify;
use Zana\Configuration\ConfigurationInterface;
use Zana\Container\Contracts\ContainerInterface;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Container\Contracts\ServiceResolverInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\ServiceProvider;
use Zana\Security\Bot\BotVerifierInterface;
use Zana\View\Markup;
use Zana\View\ViewHelpers;

/**
 * Registers the CAPTCHA provider named by captcha.provider as the bot
 * verifier for #[VerifyHuman] (2.25, FE-64): "turnstile", "recaptcha_v2",
 * "recaptcha_v3" or "hcaptcha", with captcha.secret and captcha.site_key
 * from the environment. It asks the provider through the application's
 * PSR-18 client. With mj-zana/view, the captcha_widget() helper prints the
 * provider's script and widget:
 *
 *     <?= $this->captcha_widget('contact', $csp_nonce) ?>
 *
 * Until captcha.provider names a provider, the verifier asks nobody and
 * answers unavailable, so protected forms are refused, and `check` says why.
 */
final class CaptchaServiceProvider extends ServiceProvider
{
    public function register(ServiceCollectionInterface $services): void
    {
        $services
            ->singleton(CaptchaCheck::class)
            ->tag(ApplicationCheck::TAG, CaptchaCheck::class)
            ->singleton(BotVerifierInterface::class, static function (ServiceResolverInterface $r): BotVerifierInterface {
                $config = $r->get(ConfigurationInterface::class);
                assert($config instanceof ConfigurationInterface);
                $provider = $config->get('captcha.provider');
                if (!is_string($provider) || !isset(Providers::ALL[$provider])) {
                    return new Unconfigured($provider === null ? 'captcha-provider-not-set' : 'captcha-provider-unknown');
                }
                $client = $r->has(ClientInterface::class) ? $r->get(ClientInterface::class) : null;
                $factory = new Psr17Factory();
                $secret = $config->get('captcha.secret');
                $siteKey = $config->get('captcha.site_key');

                return Providers::create(
                    $provider,
                    is_string($secret) ? $secret : '',
                    is_string($siteKey) ? $siteKey : '',
                    $client instanceof ClientInterface ? $client : null,
                    $factory,
                    $factory,
                );
            })->uses(ConfigurationInterface::class, ClientInterface::class);
    }

    public function boot(ContainerInterface $container): void
    {
        if (!class_exists(ViewHelpers::class) || !$container->has(ViewHelpers::class)) {
            return;
        }
        $helpers = $container->get(ViewHelpers::class);
        assert($helpers instanceof ViewHelpers);
        $helpers->add('captcha_widget', static function (?string $action = null, ?string $nonce = null) use ($container): Markup {
            $verifier = $container->get(BotVerifierInterface::class);

            // Nothing to show until a provider is named: the form is refused, and `check` says why.
            return new Markup($verifier instanceof SiteVerify ? $verifier->widget($action, $nonce) : '');
        }, safe: true);
    }
}
