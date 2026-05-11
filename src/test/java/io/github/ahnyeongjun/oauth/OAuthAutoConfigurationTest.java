package io.github.ahnyeongjun.oauth;

import io.github.ahnyeongjun.oauth.client.OAuthClientFactory;
import io.github.ahnyeongjun.oauth.client.google.GoogleOAuthClient;
import io.github.ahnyeongjun.oauth.client.kakao.KakaoOAuthClient;
import io.github.ahnyeongjun.oauth.config.OAuthProperties;
import io.github.ahnyeongjun.oauth.provider.OAuthProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(OAuthAutoConfiguration.class));

    @Test
    void noClientsRegisteredWithoutProperties() {
        contextRunner.run(ctx -> {
            assertThat(ctx).doesNotHaveBean(KakaoOAuthClient.class);
            assertThat(ctx).doesNotHaveBean(GoogleOAuthClient.class);
            assertThat(ctx).hasSingleBean(OAuthClientFactory.class);
            assertThat(ctx).hasSingleBean(OAuthProperties.class);
            assertThat(ctx.getBean(OAuthClientFactory.class)).isNotNull();
        });
    }

    @Test
    void kakaoClientRegisteredWhenClientIdPresent() {
        contextRunner
                .withPropertyValues("oauth.kakao.client-id=kakao-client")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(KakaoOAuthClient.class);
                    assertThat(ctx).doesNotHaveBean(GoogleOAuthClient.class);
                });
    }

    @Test
    void googleClientRegisteredWhenClientIdPresent() {
        contextRunner
                .withPropertyValues("oauth.google.client-id=google-client")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(GoogleOAuthClient.class);
                    assertThat(ctx).doesNotHaveBean(KakaoOAuthClient.class);
                });
    }

    @Test
    void bothClientsRegisteredWhenBothPropertiesPresent() {
        contextRunner
                .withPropertyValues(
                        "oauth.kakao.client-id=kakao-client",
                        "oauth.google.client-id=google-client")
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(KakaoOAuthClient.class);
                    assertThat(ctx).hasSingleBean(GoogleOAuthClient.class);
                    OAuthClientFactory factory = ctx.getBean(OAuthClientFactory.class);
                    assertThat(factory.getClient(OAuthProvider.KAKAO)).isInstanceOf(KakaoOAuthClient.class);
                    assertThat(factory.getClient(OAuthProvider.GOOGLE)).isInstanceOf(GoogleOAuthClient.class);
                });
    }

    @Test
    void defaultOAuthRestTemplateRegistered() {
        contextRunner.run(ctx -> {
            assertThat(ctx).hasBean("oAuthRestTemplate");
            assertThat(ctx.getBean("oAuthRestTemplate")).isInstanceOf(RestTemplate.class);
        });
    }

    @Test
    void userProvidedOAuthRestTemplateWins() {
        RestTemplate custom = new RestTemplate();
        contextRunner
                .withBean("oAuthRestTemplate", RestTemplate.class, () -> custom)
                .run(ctx -> assertThat(ctx.getBean("oAuthRestTemplate")).isSameAs(custom));
    }

    @Test
    void userProvidedFactoryWins() {
        OAuthClientFactory custom = new OAuthClientFactory(java.util.List.of());
        contextRunner
                .withBean(OAuthClientFactory.class, () -> custom)
                .run(ctx -> assertThat(ctx.getBean(OAuthClientFactory.class)).isSameAs(custom));
    }

}
