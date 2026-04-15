package io.github.ahnyeongjun.oauth.exception;

public class OAuthAuthenticationException extends OAuthException {

    public OAuthAuthenticationException(String provider, Throwable cause) {
        super(provider + " OAuth 인증에 실패했습니다.", cause);
    }
}
