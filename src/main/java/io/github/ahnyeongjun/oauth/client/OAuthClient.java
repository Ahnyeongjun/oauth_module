package io.github.ahnyeongjun.oauth.client;

import io.github.ahnyeongjun.oauth.dto.OAuthUserInfo;
import io.github.ahnyeongjun.oauth.provider.OAuthProvider;

public interface OAuthClient {

    OAuthProvider getProvider();

    String getAccessToken(String code, String redirectUri);

    OAuthUserInfo getUserInfo(String accessToken);
}
