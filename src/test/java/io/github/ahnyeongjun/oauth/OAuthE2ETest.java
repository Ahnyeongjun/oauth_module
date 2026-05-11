package io.github.ahnyeongjun.oauth;

import io.github.ahnyeongjun.oauth.client.OAuthClient;
import io.github.ahnyeongjun.oauth.client.OAuthClientFactory;
import io.github.ahnyeongjun.oauth.dto.OAuthUserInfo;
import io.github.ahnyeongjun.oauth.exception.OAuthAuthenticationException;
import io.github.ahnyeongjun.oauth.provider.OAuthProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import org.springframework.http.HttpStatus;

@DisplayName("OAuth E2E 통합 테스트 - 실제 Auto-Configuration 컨텍스트에서의 전체 흐름")
class OAuthE2ETest {

    private final ApplicationContextRunner baseRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(OAuthAutoConfiguration.class));

    // ── Google ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Google: code → access_token → userInfo 전체 흐름")
    void googleCompleteFlow() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer mockServer = MockRestServiceServer.createServer(restTemplate);

        mockServer.expect(requestTo("https://oauth2.googleapis.com/token"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"access_token\":\"google-access-token\",\"token_type\":\"Bearer\"}",
                        MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo("https://openidconnect.googleapis.com/v1/userinfo"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("""
                        {"sub":"g-sub-001","email":"user@gmail.com","name":"홍길동","picture":"https://photo.jpg"}
                        """, MediaType.APPLICATION_JSON));

        baseRunner
                .withBean("oAuthRestTemplate", RestTemplate.class, () -> restTemplate)
                .withPropertyValues(
                        "oauth.google.client-id=real-client-id",
                        "oauth.google.client-secret=real-client-secret",
                        "oauth.google.token-url=https://oauth2.googleapis.com/token",
                        "oauth.google.user-info-url=https://openidconnect.googleapis.com/v1/userinfo")
                .run(ctx -> {
                    OAuthClientFactory factory = ctx.getBean(OAuthClientFactory.class);
                    OAuthClient client = factory.getClient("google");

                    String token = client.getAccessToken("authorization-code", "https://myapp.com/callback");
                    OAuthUserInfo userInfo = client.getUserInfo(token);

                    assertThat(token).isEqualTo("google-access-token");
                    assertThat(userInfo.getProvider()).isEqualTo(OAuthProvider.GOOGLE);
                    assertThat(userInfo.getProviderId()).isEqualTo("g-sub-001");
                    assertThat(userInfo.getEmail()).isEqualTo("user@gmail.com");
                    assertThat(userInfo.getNickname()).isEqualTo("홍길동");
                    assertThat(userInfo.getProfileImage()).isEqualTo("https://photo.jpg");
                    mockServer.verify();
                });
    }

    @Test
    @DisplayName("Google: name 필드 없을 때 '구글유저' 기본값이 전체 흐름에서 적용")
    void googleDefaultNicknameInFullFlow() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer mockServer = MockRestServiceServer.createServer(restTemplate);

        mockServer.expect(requestTo("https://oauth2.googleapis.com/token"))
                .andRespond(withSuccess("{\"access_token\":\"g-token\"}", MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo("https://openidconnect.googleapis.com/v1/userinfo"))
                .andRespond(withSuccess("{\"sub\":\"g-1\",\"email\":\"anon@gmail.com\"}", MediaType.APPLICATION_JSON));

        baseRunner
                .withBean("oAuthRestTemplate", RestTemplate.class, () -> restTemplate)
                .withPropertyValues(
                        "oauth.google.client-id=g-id", "oauth.google.client-secret=g-sec",
                        "oauth.google.token-url=https://oauth2.googleapis.com/token",
                        "oauth.google.user-info-url=https://openidconnect.googleapis.com/v1/userinfo")
                .run(ctx -> {
                    OAuthClient client = ctx.getBean(OAuthClientFactory.class).getClient(OAuthProvider.GOOGLE);
                    OAuthUserInfo userInfo = client.getUserInfo(client.getAccessToken("code", "uri"));

                    assertThat(userInfo.getNickname()).isEqualTo("구글유저");
                    assertThat(userInfo.getProfileImage()).isNull();
                    mockServer.verify();
                });
    }

    // ── Kakao ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Kakao: code → access_token → userInfo 전체 흐름")
    void kakaoCompleteFlow() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer mockServer = MockRestServiceServer.createServer(restTemplate);

        mockServer.expect(requestTo("https://kauth.kakao.com/oauth/token"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"access_token\":\"kakao-access-token\",\"token_type\":\"bearer\"}",
                        MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo("https://kapi.kakao.com/v2/user/me"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("""
                        {
                          "id": 112233,
                          "kakao_account": {
                            "email": "user@kakao.com",
                            "profile": {
                              "nickname": "김철수",
                              "profile_image_url": "https://cdn.kakao.com/profile.jpg"
                            }
                          }
                        }
                        """, MediaType.APPLICATION_JSON));

        baseRunner
                .withBean("oAuthRestTemplate", RestTemplate.class, () -> restTemplate)
                .withPropertyValues(
                        "oauth.kakao.client-id=kakao-client-id",
                        "oauth.kakao.client-secret=kakao-client-secret",
                        "oauth.kakao.token-url=https://kauth.kakao.com/oauth/token",
                        "oauth.kakao.user-info-url=https://kapi.kakao.com/v2/user/me")
                .run(ctx -> {
                    OAuthClientFactory factory = ctx.getBean(OAuthClientFactory.class);
                    OAuthClient client = factory.getClient(OAuthProvider.KAKAO);

                    String token = client.getAccessToken("kakao-code", "https://myapp.com/kakao/callback");
                    OAuthUserInfo userInfo = client.getUserInfo(token);

                    assertThat(token).isEqualTo("kakao-access-token");
                    assertThat(userInfo.getProvider()).isEqualTo(OAuthProvider.KAKAO);
                    assertThat(userInfo.getProviderId()).isEqualTo("112233");
                    assertThat(userInfo.getEmail()).isEqualTo("user@kakao.com");
                    assertThat(userInfo.getNickname()).isEqualTo("김철수");
                    mockServer.verify();
                });
    }

    @Test
    @DisplayName("Kakao: 이메일 미동의 시 전체 흐름에서 kakao_{id}@kakao.com fallback 적용")
    void kakaoEmailFallbackInFullFlow() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer mockServer = MockRestServiceServer.createServer(restTemplate);

        mockServer.expect(requestTo("https://kauth.kakao.com/oauth/token"))
                .andRespond(withSuccess("{\"access_token\":\"k-token\"}", MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo("https://kapi.kakao.com/v2/user/me"))
                .andRespond(withSuccess("""
                        {"id": 55555, "kakao_account": {"profile": {"nickname": "익명유저"}}}
                        """, MediaType.APPLICATION_JSON));

        baseRunner
                .withBean("oAuthRestTemplate", RestTemplate.class, () -> restTemplate)
                .withPropertyValues(
                        "oauth.kakao.client-id=k-id", "oauth.kakao.client-secret=k-sec",
                        "oauth.kakao.token-url=https://kauth.kakao.com/oauth/token",
                        "oauth.kakao.user-info-url=https://kapi.kakao.com/v2/user/me")
                .run(ctx -> {
                    OAuthClient client = ctx.getBean(OAuthClientFactory.class).getClient(OAuthProvider.KAKAO);
                    OAuthUserInfo userInfo = client.getUserInfo(client.getAccessToken("code", "uri"));

                    assertThat(userInfo.getEmail()).isEqualTo("kakao_55555@kakao.com");
                    assertThat(userInfo.getNickname()).isEqualTo("익명유저");
                    mockServer.verify();
                });
    }

    // ── 두 Provider 동시 활성 ────────────────────────────────────────────────

    @Test
    @DisplayName("두 provider 동시 등록: Google·Kakao 흐름이 동일 컨텍스트에서 독립적으로 동작")
    void bothProvidersActiveInSameContext() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer mockServer = MockRestServiceServer.createServer(restTemplate);

        // MockRestServiceServer는 등록 순서대로 매칭 → 호출 순서를 맞춰 기대값 등록
        mockServer.expect(requestTo("https://oauth2.googleapis.com/token"))
                .andRespond(withSuccess("{\"access_token\":\"g-token\"}", MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo("https://openidconnect.googleapis.com/v1/userinfo"))
                .andRespond(withSuccess("{\"sub\":\"g-1\",\"email\":\"g@gmail.com\",\"name\":\"구글\"}", MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo("https://kauth.kakao.com/oauth/token"))
                .andRespond(withSuccess("{\"access_token\":\"k-token\"}", MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo("https://kapi.kakao.com/v2/user/me"))
                .andRespond(withSuccess("""
                        {"id":9,"kakao_account":{"email":"k@kakao.com","profile":{"nickname":"카카오"}}}
                        """, MediaType.APPLICATION_JSON));

        baseRunner
                .withBean("oAuthRestTemplate", RestTemplate.class, () -> restTemplate)
                .withPropertyValues(
                        "oauth.google.client-id=g-id", "oauth.google.client-secret=g-sec",
                        "oauth.google.token-url=https://oauth2.googleapis.com/token",
                        "oauth.google.user-info-url=https://openidconnect.googleapis.com/v1/userinfo",
                        "oauth.kakao.client-id=k-id", "oauth.kakao.client-secret=k-sec",
                        "oauth.kakao.token-url=https://kauth.kakao.com/oauth/token",
                        "oauth.kakao.user-info-url=https://kapi.kakao.com/v2/user/me")
                .run(ctx -> {
                    OAuthClientFactory factory = ctx.getBean(OAuthClientFactory.class);

                    OAuthClient googleClient = factory.getClient(OAuthProvider.GOOGLE);
                    OAuthUserInfo googleUser = googleClient.getUserInfo(
                            googleClient.getAccessToken("g-code", "g-uri"));

                    OAuthClient kakaoClient = factory.getClient(OAuthProvider.KAKAO);
                    OAuthUserInfo kakaoUser = kakaoClient.getUserInfo(
                            kakaoClient.getAccessToken("k-code", "k-uri"));

                    assertThat(googleUser.getEmail()).isEqualTo("g@gmail.com");
                    assertThat(googleUser.getProvider()).isEqualTo(OAuthProvider.GOOGLE);
                    assertThat(kakaoUser.getEmail()).isEqualTo("k@kakao.com");
                    assertThat(kakaoUser.getProvider()).isEqualTo(OAuthProvider.KAKAO);
                    mockServer.verify();
                });
    }

    // ── 예외 전파 ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("토큰 발급 실패(5xx) 시 예외가 전파되고 userInfo 호출은 일어나지 않는다")
    void tokenServerFailurePreventsUserInfoCall() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer mockServer = MockRestServiceServer.createServer(restTemplate);

        mockServer.expect(requestTo("https://oauth2.googleapis.com/token"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withServerError());

        baseRunner
                .withBean("oAuthRestTemplate", RestTemplate.class, () -> restTemplate)
                .withPropertyValues(
                        "oauth.google.client-id=test-id", "oauth.google.client-secret=test-secret",
                        "oauth.google.token-url=https://oauth2.googleapis.com/token",
                        "oauth.google.user-info-url=https://openidconnect.googleapis.com/v1/userinfo")
                .run(ctx -> {
                    OAuthClient client = ctx.getBean(OAuthClientFactory.class).getClient(OAuthProvider.GOOGLE);

                    assertThatThrownBy(() -> {
                        String token = client.getAccessToken("bad-code", "https://myapp.com/callback");
                        client.getUserInfo(token);
                    }).isInstanceOf(OAuthAuthenticationException.class)
                      .hasMessageContaining("Google");

                    mockServer.verify();
                });
    }

    @Test
    @DisplayName("userInfo 조회 실패(401) 시 OAuthAuthenticationException이 전파된다")
    void userInfoUnauthorizedPropagates() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer mockServer = MockRestServiceServer.createServer(restTemplate);

        mockServer.expect(requestTo("https://kauth.kakao.com/oauth/token"))
                .andRespond(withSuccess("{\"access_token\":\"expired-token\"}", MediaType.APPLICATION_JSON));
        mockServer.expect(requestTo("https://kapi.kakao.com/v2/user/me"))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED));

        baseRunner
                .withBean("oAuthRestTemplate", RestTemplate.class, () -> restTemplate)
                .withPropertyValues(
                        "oauth.kakao.client-id=k-id", "oauth.kakao.client-secret=k-sec",
                        "oauth.kakao.token-url=https://kauth.kakao.com/oauth/token",
                        "oauth.kakao.user-info-url=https://kapi.kakao.com/v2/user/me")
                .run(ctx -> {
                    OAuthClient client = ctx.getBean(OAuthClientFactory.class).getClient(OAuthProvider.KAKAO);
                    String token = client.getAccessToken("code", "uri");

                    assertThatThrownBy(() -> client.getUserInfo(token))
                            .isInstanceOf(OAuthAuthenticationException.class)
                            .hasMessageContaining("Kakao");

                    mockServer.verify();
                });
    }
}
