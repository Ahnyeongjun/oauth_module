package io.github.ahnyeongjun.oauth.factory;

import io.github.ahnyeongjun.oauth.client.OAuthClient;
import io.github.ahnyeongjun.oauth.client.OAuthClientFactory;
import io.github.ahnyeongjun.oauth.dto.OAuthUserInfo;
import io.github.ahnyeongjun.oauth.exception.UnsupportedProviderException;
import io.github.ahnyeongjun.oauth.provider.OAuthProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OAuthClientFactoryTest {

    private OAuthClientFactory factory;
    private OAuthClient kakaoClient;
    private OAuthClient googleClient;

    @BeforeEach
    void setUp() {
        kakaoClient = new StubOAuthClient(OAuthProvider.KAKAO);
        googleClient = new StubOAuthClient(OAuthProvider.GOOGLE);
        factory = new OAuthClientFactory(List.of(kakaoClient, googleClient));
    }

    @Test
    @DisplayName("OAuthProvider enum으로 클라이언트를 가져온다")
    void getClient_byEnum() {
        assertThat(factory.getClient(OAuthProvider.KAKAO)).isSameAs(kakaoClient);
        assertThat(factory.getClient(OAuthProvider.GOOGLE)).isSameAs(googleClient);
    }

    @Test
    @DisplayName("문자열로 클라이언트를 가져온다 (대소문자 무관)")
    void getClient_byString() {
        assertThat(factory.getClient("kakao")).isSameAs(kakaoClient);
        assertThat(factory.getClient("GOOGLE")).isSameAs(googleClient);
        assertThat(factory.getClient("Kakao")).isSameAs(kakaoClient);
    }

    @Test
    @DisplayName("등록되지 않은 제공자 요청 시 UnsupportedProviderException을 던진다")
    void getClient_unsupportedProvider() {
        assertThatThrownBy(() -> factory.getClient("naver"))
                .isInstanceOf(UnsupportedProviderException.class)
                .hasMessageContaining("naver");
    }

    @Test
    @DisplayName("null 문자열 요청 시 UnsupportedProviderException을 던진다")
    void getClient_nullString() {
        assertThatThrownBy(() -> factory.getClient((String) null))
                .isInstanceOf(UnsupportedProviderException.class);
    }

    @Test
    @DisplayName("빈 문자열 요청 시 UnsupportedProviderException을 던진다")
    void getClient_emptyString() {
        assertThatThrownBy(() -> factory.getClient(""))
                .isInstanceOf(UnsupportedProviderException.class);
    }

    @Test
    @DisplayName("공백 문자열 요청 시 UnsupportedProviderException을 던진다")
    void getClient_whitespace() {
        assertThatThrownBy(() -> factory.getClient("   "))
                .isInstanceOf(UnsupportedProviderException.class);
    }

    @Test
    @DisplayName("동일 provider를 중복 등록하면 IllegalArgumentException을 던진다")
    void duplicateProvider_throwsException() {
        StubOAuthClient kakao1 = new StubOAuthClient(OAuthProvider.KAKAO);
        StubOAuthClient kakao2 = new StubOAuthClient(OAuthProvider.KAKAO);

        assertThatThrownBy(() -> new OAuthClientFactory(List.of(kakao1, kakao2)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("KAKAO");
    }

    // 테스트용 stub 구현체
    private record StubOAuthClient(OAuthProvider provider) implements OAuthClient {

        @Override
        public OAuthProvider getProvider() {
            return provider;
        }

        @Override
        public String getAccessToken(String code, String redirectUri) {
            return "stub-token";
        }

        @Override
        public OAuthUserInfo getUserInfo(String accessToken) {
            return OAuthUserInfo.builder()
                    .providerId("stub-id")
                    .email("stub@test.com")
                    .nickname("stub")
                    .provider(provider)
                    .build();
        }
    }
}
