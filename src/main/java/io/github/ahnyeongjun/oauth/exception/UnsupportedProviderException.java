package io.github.ahnyeongjun.oauth.exception;

public class UnsupportedProviderException extends OAuthException {

    public UnsupportedProviderException(String provider) {
        super("지원하지 않는 OAuth 제공자입니다: " + provider);
    }
}
