package io.github.ahnyeongjun.oauth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "oauth")
public class OAuthProperties {

    private ProviderProperties kakao = new ProviderProperties();
    private ProviderProperties google = new ProviderProperties();

    @Getter
    @Setter
    public static class ProviderProperties {
        private String clientId;
        private String clientSecret;
        private String tokenUrl;
        private String userInfoUrl;
    }
}
