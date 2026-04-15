package io.github.ahnyeongjun.oauth.client;

import io.github.ahnyeongjun.oauth.client.kakao.KakaoOAuthClient;
import io.github.ahnyeongjun.oauth.config.OAuthProperties;
import io.github.ahnyeongjun.oauth.dto.OAuthUserInfo;
import io.github.ahnyeongjun.oauth.exception.OAuthAuthenticationException;
import io.github.ahnyeongjun.oauth.provider.OAuthProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class KakaoOAuthClientTest {

    private MockRestServiceServer mockServer;
    private KakaoOAuthClient kakaoOAuthClient;

    @BeforeEach
    void setUp() {
        RestTemplate restTemplate = new RestTemplate();
        mockServer = MockRestServiceServer.createServer(restTemplate);

        OAuthProperties properties = new OAuthProperties();
        OAuthProperties.ProviderProperties kakao = new OAuthProperties.ProviderProperties();
        kakao.setClientId("test-client-id");
        kakao.setClientSecret("test-client-secret");
        kakao.setTokenUrl("https://kauth.kakao.com/oauth/token");
        kakao.setUserInfoUrl("https://kapi.kakao.com/v2/user/me");
        properties.setKakao(kakao);

        kakaoOAuthClient = new KakaoOAuthClient(restTemplate, properties);
    }

    @Test
    @DisplayName("getProvider()는 KAKAO를 반환한다")
    void getProvider() {
        assertThat(kakaoOAuthClient.getProvider()).isEqualTo(OAuthProvider.KAKAO);
    }

    @Test
    @DisplayName("유효한 code로 access token을 발급받는다")
    void getAccessToken_success() {
        mockServer.expect(requestTo("https://kauth.kakao.com/oauth/token"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"access_token\": \"kakao-access-token\", \"token_type\": \"bearer\"}",
                        MediaType.APPLICATION_JSON));

        String token = kakaoOAuthClient.getAccessToken("auth-code", "http://localhost/callback");

        assertThat(token).isEqualTo("kakao-access-token");
        mockServer.verify();
    }

    @Test
    @DisplayName("카카오 서버 오류 시 OAuthAuthenticationException을 던진다")
    void getAccessToken_serverError() {
        mockServer.expect(requestTo("https://kauth.kakao.com/oauth/token"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withServerError());

        assertThatThrownBy(() -> kakaoOAuthClient.getAccessToken("bad-code", "http://localhost/callback"))
                .isInstanceOf(OAuthAuthenticationException.class)
                .hasMessageContaining("Kakao");
    }

    @Test
    @DisplayName("access token으로 사용자 정보를 조회한다")
    void getUserInfo_success() {
        mockServer.expect(requestTo("https://kapi.kakao.com/v2/user/me"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer test-token"))
                .andRespond(withSuccess("""
                        {
                          "id": 12345,
                          "kakao_account": {
                            "email": "user@kakao.com",
                            "profile": {
                              "nickname": "테스트유저",
                              "profile_image_url": "https://example.com/profile.jpg"
                            }
                          }
                        }
                        """, MediaType.APPLICATION_JSON));

        OAuthUserInfo userInfo = kakaoOAuthClient.getUserInfo("test-token");

        assertThat(userInfo.getProviderId()).isEqualTo("12345");
        assertThat(userInfo.getEmail()).isEqualTo("user@kakao.com");
        assertThat(userInfo.getNickname()).isEqualTo("테스트유저");
        assertThat(userInfo.getProfileImage()).isEqualTo("https://example.com/profile.jpg");
        assertThat(userInfo.getProvider()).isEqualTo(OAuthProvider.KAKAO);
        mockServer.verify();
    }

    @Test
    @DisplayName("이메일 동의 없을 때 kakao_{id}@kakao.com으로 대체한다")
    void getUserInfo_noEmail_usesFallback() {
        mockServer.expect(requestTo("https://kapi.kakao.com/v2/user/me"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("""
                        {
                          "id": 99999,
                          "kakao_account": {
                            "profile": {
                              "nickname": "이메일없는유저"
                            }
                          }
                        }
                        """, MediaType.APPLICATION_JSON));

        OAuthUserInfo userInfo = kakaoOAuthClient.getUserInfo("test-token");

        assertThat(userInfo.getEmail()).isEqualTo("kakao_99999@kakao.com");
    }
}
