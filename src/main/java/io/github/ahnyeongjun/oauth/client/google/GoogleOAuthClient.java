package io.github.ahnyeongjun.oauth.client.google;

import io.github.ahnyeongjun.oauth.client.OAuthClient;
import io.github.ahnyeongjun.oauth.config.OAuthProperties;
import io.github.ahnyeongjun.oauth.dto.OAuthUserInfo;
import io.github.ahnyeongjun.oauth.exception.OAuthAuthenticationException;
import io.github.ahnyeongjun.oauth.provider.OAuthProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Slf4j
public class GoogleOAuthClient implements OAuthClient {

    private final RestTemplate restTemplate;
    private final OAuthProperties.ProviderProperties properties;

    public GoogleOAuthClient(RestTemplate restTemplate, OAuthProperties properties) {
        this.restTemplate = restTemplate;
        this.properties = properties.getGoogle();
    }

    @Override
    public OAuthProvider getProvider() {
        return OAuthProvider.GOOGLE;
    }

    @Override
    public String getAccessToken(String code, String redirectUri) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "authorization_code");
            params.add("client_id", properties.getClientId());
            params.add("client_secret", properties.getClientSecret());
            params.add("redirect_uri", redirectUri);
            params.add("code", code);

            ResponseEntity<Map> response = restTemplate.exchange(
                    properties.getTokenUrl(), HttpMethod.POST,
                    new HttpEntity<>(params, headers), Map.class);

            return (String) response.getBody().get("access_token");
        } catch (RestClientException e) {
            log.error("Failed to get Google access token", e);
            throw new OAuthAuthenticationException("Google", e);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public OAuthUserInfo getUserInfo(String accessToken) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);

            ResponseEntity<Map> response = restTemplate.exchange(
                    properties.getUserInfoUrl(), HttpMethod.GET,
                    new HttpEntity<>(headers), Map.class);

            Map<String, Object> body = response.getBody();
            String providerId = (String) body.get("sub");
            String email = (String) body.get("email");
            String nickname = (String) body.get("name");
            String profileImage = (String) body.get("picture");

            if (nickname == null) {
                nickname = "구글유저";
            }

            return OAuthUserInfo.builder()
                    .providerId(providerId)
                    .email(email)
                    .nickname(nickname)
                    .profileImage(profileImage)
                    .provider(OAuthProvider.GOOGLE)
                    .build();
        } catch (RestClientException e) {
            log.error("Failed to get Google user info", e);
            throw new OAuthAuthenticationException("Google", e);
        }
    }
}
