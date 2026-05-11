package io.github.ahnyeongjun.oauth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthPropertiesTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(EnablePropertiesConfig.class);

    @Test
    void bindsKakaoProperties() {
        contextRunner
                .withPropertyValues(
                        "oauth.kakao.client-id=k-id",
                        "oauth.kakao.client-secret=k-secret",
                        "oauth.kakao.token-url=https://kauth.kakao.com/oauth/token",
                        "oauth.kakao.user-info-url=https://kapi.kakao.com/v2/user/me")
                .run(ctx -> {
                    OAuthProperties props = ctx.getBean(OAuthProperties.class);
                    assertThat(props.getKakao().getClientId()).isEqualTo("k-id");
                    assertThat(props.getKakao().getClientSecret()).isEqualTo("k-secret");
                    assertThat(props.getKakao().getTokenUrl()).isEqualTo("https://kauth.kakao.com/oauth/token");
                    assertThat(props.getKakao().getUserInfoUrl()).isEqualTo("https://kapi.kakao.com/v2/user/me");
                });
    }

    @Test
    void bindsGoogleProperties() {
        contextRunner
                .withPropertyValues(
                        "oauth.google.client-id=g-id",
                        "oauth.google.client-secret=g-secret",
                        "oauth.google.token-url=https://oauth2.googleapis.com/token",
                        "oauth.google.user-info-url=https://openidconnect.googleapis.com/v1/userinfo")
                .run(ctx -> {
                    OAuthProperties props = ctx.getBean(OAuthProperties.class);
                    assertThat(props.getGoogle().getClientId()).isEqualTo("g-id");
                    assertThat(props.getGoogle().getClientSecret()).isEqualTo("g-secret");
                    assertThat(props.getGoogle().getTokenUrl()).isEqualTo("https://oauth2.googleapis.com/token");
                    assertThat(props.getGoogle().getUserInfoUrl())
                            .isEqualTo("https://openidconnect.googleapis.com/v1/userinfo");
                });
    }

    @Test
    void emptyPropertiesYieldNullFields() {
        contextRunner.run(ctx -> {
            OAuthProperties props = ctx.getBean(OAuthProperties.class);
            assertThat(props.getKakao()).isNotNull();
            assertThat(props.getKakao().getClientId()).isNull();
            assertThat(props.getGoogle()).isNotNull();
            assertThat(props.getGoogle().getClientId()).isNull();
        });
    }

    @EnableConfigurationProperties(OAuthProperties.class)
    static class EnablePropertiesConfig {
    }
}
