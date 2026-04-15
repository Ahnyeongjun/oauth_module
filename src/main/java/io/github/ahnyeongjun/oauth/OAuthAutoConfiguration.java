package io.github.ahnyeongjun.oauth;

import io.github.ahnyeongjun.oauth.client.OAuthClient;
import io.github.ahnyeongjun.oauth.client.OAuthClientFactory;
import io.github.ahnyeongjun.oauth.client.google.GoogleOAuthClient;
import io.github.ahnyeongjun.oauth.client.kakao.KakaoOAuthClient;
import io.github.ahnyeongjun.oauth.config.OAuthProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@AutoConfiguration
@ConditionalOnClass(RestTemplate.class)
@EnableConfigurationProperties(OAuthProperties.class)
public class OAuthAutoConfiguration {

    /**
     * 애플리케이션에 RestTemplate 빈이 없을 때만 등록.
     * 기존에 RestTemplate을 직접 설정한 경우 그것을 그대로 사용.
     */
    @Bean("oAuthRestTemplate")
    @ConditionalOnMissingBean(name = "oAuthRestTemplate")
    public RestTemplate oAuthRestTemplate() {
        return new RestTemplate();
    }

    @Bean
    @ConditionalOnProperty(prefix = "oauth.kakao", name = "client-id")
    public KakaoOAuthClient kakaoOAuthClient(RestTemplate oAuthRestTemplate, OAuthProperties properties) {
        return new KakaoOAuthClient(oAuthRestTemplate, properties);
    }

    @Bean
    @ConditionalOnProperty(prefix = "oauth.google", name = "client-id")
    public GoogleOAuthClient googleOAuthClient(RestTemplate oAuthRestTemplate, OAuthProperties properties) {
        return new GoogleOAuthClient(oAuthRestTemplate, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public OAuthClientFactory oAuthClientFactory(List<OAuthClient> oAuthClients) {
        return new OAuthClientFactory(oAuthClients);
    }
}
