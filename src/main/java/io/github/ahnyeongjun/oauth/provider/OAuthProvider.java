package io.github.ahnyeongjun.oauth.provider;

import java.util.Arrays;
import java.util.Optional;

public enum OAuthProvider {
    KAKAO,
    GOOGLE;

    public static Optional<OAuthProvider> fromString(String value) {
        if (value == null) {
            return Optional.empty();
        }
        return Arrays.stream(values())
                .filter(p -> p.name().equalsIgnoreCase(value))
                .findFirst();
    }
}
