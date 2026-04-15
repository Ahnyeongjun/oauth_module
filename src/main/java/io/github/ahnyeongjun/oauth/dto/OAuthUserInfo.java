package io.github.ahnyeongjun.oauth.dto;

import io.github.ahnyeongjun.oauth.provider.OAuthProvider;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class OAuthUserInfo {

    private final String providerId;
    private final String email;
    private final String nickname;
    private final String profileImage;
    private final OAuthProvider provider;
}
