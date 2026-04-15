package io.github.ahnyeongjun.oauth.client;

import io.github.ahnyeongjun.oauth.client.google.GoogleOAuthClient;
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

class GoogleOAuthClientTest {

    private MockRestServiceServer mockServer;
    private GoogleOAuthClient googleOAuthClient;

    @BeforeEach
    void setUp() {
        RestTemplate restTemplate = new RestTemplate();
        mockServer = MockRestServiceServer.createServer(restTemplate);

        OAuthProperties properties = new OAuthProperties();
        OAuthProperties.ProviderProperties google = new OAuthProperties.ProviderProperties();
        google.setClientId("test-google-client-id");
        google.setClientSecret("test-google-client-secret");
        google.setTokenUrl("https://oauth2.googleapis.com/token");
        google.setUserInfoUrl("https://www.googleapis.com/oauth2/v2/userinfo");
        properties.setGoogle(google);

        googleOAuthClient = new GoogleOAuthClient(restTemplate, properties);
    }

    @Test
    @DisplayName("getProvider()는 GOOGLE을 반환한다")
    void getProvider() {
        assertThat(googleOAuthClient.getProvider()).isEqualTo(OAuthProvider.GOOGLE);
    }

    @Test
    @DisplayName("유효한 code로 access token을 발급받는다")
    void getAccessToken_success() {
        mockServer.expect(requestTo("https://oauth2.googleapis.com/token"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"access_token\": \"google-access-token\", \"token_type\": \"Bearer\"}",
                        MediaType.APPLICATION_JSON));

        String token = googleOAuthClient.getAccessToken("auth-code", "http://localhost/callback");

        assertThat(token).isEqualTo("google-access-token");
        mockServer.verify();
    }

    @Test
    @DisplayName("구글 서버 오류 시 OAuthAuthenticationException을 던진다")
    void getAccessToken_serverError() {
        mockServer.expect(requestTo("https://oauth2.googleapis.com/token"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withServerError());

        assertThatThrownBy(() -> googleOAuthClient.getAccessToken("bad-code", "http://localhost/callback"))
                .isInstanceOf(OAuthAuthenticationException.class)
                .hasMessageContaining("Google");
    }

    @Test
    @DisplayName("access token으로 사용자 정보를 조회한다")
    void getUserInfo_success() {
        mockServer.expect(requestTo("https://www.googleapis.com/oauth2/v2/userinfo"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer test-token"))
                .andRespond(withSuccess("""
                        {
                          "id": "google-user-id",
                          "email": "user@gmail.com",
                          "name": "테스트유저",
                          "picture": "https://example.com/photo.jpg"
                        }
                        """, MediaType.APPLICATION_JSON));

        OAuthUserInfo userInfo = googleOAuthClient.getUserInfo("test-token");

        assertThat(userInfo.getProviderId()).isEqualTo("google-user-id");
        assertThat(userInfo.getEmail()).isEqualTo("user@gmail.com");
        assertThat(userInfo.getNickname()).isEqualTo("테스트유저");
        assertThat(userInfo.getProfileImage()).isEqualTo("https://example.com/photo.jpg");
        assertThat(userInfo.getProvider()).isEqualTo(OAuthProvider.GOOGLE);
        mockServer.verify();
    }

    @Test
    @DisplayName("name이 null이면 기본값 '구글유저'를 사용한다")
    void getUserInfo_noName_usesDefault() {
        mockServer.expect(requestTo("https://www.googleapis.com/oauth2/v2/userinfo"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("""
                        {
                          "id": "google-user-id",
                          "email": "user@gmail.com"
                        }
                        """, MediaType.APPLICATION_JSON));

        OAuthUserInfo userInfo = googleOAuthClient.getUserInfo("test-token");

        assertThat(userInfo.getNickname()).isEqualTo("구글유저");
    }
}
