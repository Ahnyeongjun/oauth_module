package io.github.ahnyeongjun.oauth;

import io.github.ahnyeongjun.oauth.client.OAuthClient;
import io.github.ahnyeongjun.oauth.client.OAuthClientFactory;
import io.github.ahnyeongjun.oauth.client.google.GoogleOAuthClient;
import io.github.ahnyeongjun.oauth.client.kakao.KakaoOAuthClient;
import io.github.ahnyeongjun.oauth.config.OAuthProperties;
import io.github.ahnyeongjun.oauth.dto.OAuthUserInfo;
import io.github.ahnyeongjun.oauth.provider.OAuthProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("OAuth 동시성 테스트")
class OAuthConcurrencyTest {

    // ── 테스트용 스텁 JSON ────────────────────────────────────────────────────

    private static final String GOOGLE_TOKEN_JSON =
            "{\"access_token\":\"google-token\",\"token_type\":\"Bearer\"}";
    private static final String GOOGLE_USER_JSON =
            "{\"sub\":\"g-123\",\"email\":\"user@gmail.com\",\"name\":\"구글유저\"}";
    private static final String KAKAO_TOKEN_JSON =
            "{\"access_token\":\"kakao-token\",\"token_type\":\"bearer\"}";
    private static final String KAKAO_USER_JSON =
            "{\"id\":12345,\"kakao_account\":{\"email\":\"user@kakao.com\",\"profile\":{\"nickname\":\"카카오유저\"}}}";

    /**
     * URL에 "token"이 포함되면 토큰 응답, 아니면 userInfo 응답을 반환하는
     * 상태 없는(stateless) 인터셉터 기반 스텁 RestTemplate.
     * 람다가 캡처하는 값이 불변이므로 멀티스레드 환경에서 안전하게 공유 가능.
     */
    private static RestTemplate stubRestTemplate(String tokenJson, String userInfoJson) {
        RestTemplate rt = new RestTemplate();
        rt.setInterceptors(List.of((request, body, execution) -> {
            String json = request.getURI().toString().contains("token") ? tokenJson : userInfoJson;
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            HttpHeaders responseHeaders = new HttpHeaders();
            responseHeaders.setContentType(MediaType.APPLICATION_JSON);
            return new ClientHttpResponse() {
                @Override public org.springframework.http.HttpStatusCode getStatusCode() { return HttpStatus.OK; }
                @Override public String getStatusText() { return "OK"; }
                @Override public HttpHeaders getHeaders() { return responseHeaders; }
                @Override public InputStream getBody() { return new ByteArrayInputStream(bytes); }
                @Override public void close() {}
            };
        }));
        return rt;
    }

    private static OAuthProperties googleProperties() {
        OAuthProperties props = new OAuthProperties();
        OAuthProperties.ProviderProperties p = new OAuthProperties.ProviderProperties();
        p.setClientId("g-id");
        p.setClientSecret("g-sec");
        p.setTokenUrl("https://oauth2.googleapis.com/token");
        p.setUserInfoUrl("https://openidconnect.googleapis.com/v1/userinfo");
        props.setGoogle(p);
        return props;
    }

    private static OAuthProperties kakaoProperties() {
        OAuthProperties props = new OAuthProperties();
        OAuthProperties.ProviderProperties p = new OAuthProperties.ProviderProperties();
        p.setClientId("k-id");
        p.setClientSecret("k-sec");
        p.setTokenUrl("https://kauth.kakao.com/oauth/token");
        p.setUserInfoUrl("https://kapi.kakao.com/v2/user/me");
        props.setKakao(p);
        return props;
    }

    // ── OAuthClientFactory 동시성 ────────────────────────────────────────────

    @Test
    @DisplayName("OAuthClientFactory: 100 스레드 동시 getClient() → 모두 올바른 인스턴스 반환")
    void factoryConcurrentAccess() throws InterruptedException {
        GoogleOAuthClient googleClient = new GoogleOAuthClient(
                stubRestTemplate(GOOGLE_TOKEN_JSON, GOOGLE_USER_JSON), googleProperties());
        KakaoOAuthClient kakaoClient = new KakaoOAuthClient(
                stubRestTemplate(KAKAO_TOKEN_JSON, KAKAO_USER_JSON), kakaoProperties());
        OAuthClientFactory factory = new OAuthClientFactory(List.of(googleClient, kakaoClient));

        int threadCount = 100;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threadCount);
        AtomicInteger errors = new AtomicInteger(0);
        // CopyOnWriteArrayList는 멀티스레드 쓰기에 안전
        java.util.List<OAuthProvider> results = new java.util.concurrent.CopyOnWriteArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            OAuthProvider target = (i % 2 == 0) ? OAuthProvider.GOOGLE : OAuthProvider.KAKAO;
            new Thread(() -> {
                try {
                    start.await();
                    results.add(factory.getClient(target).getProvider());
                } catch (Exception e) {
                    errors.incrementAndGet();
                } finally {
                    done.countDown();
                }
            }).start();
        }

        start.countDown();
        assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();

        assertThat(errors.get()).isZero();
        assertThat(results).hasSize(threadCount);
        assertThat(results.stream().filter(p -> p == OAuthProvider.GOOGLE).count()).isEqualTo(50);
        assertThat(results.stream().filter(p -> p == OAuthProvider.KAKAO).count()).isEqualTo(50);
    }

    // ── getAccessToken 동시성 ────────────────────────────────────────────────

    @Test
    @DisplayName("GoogleOAuthClient: 30 스레드 동시 getAccessToken() → 오류 없이 모두 완료")
    void concurrentGoogleTokenAcquisition() throws InterruptedException {
        // RestTemplate은 스레드 안전 → 단일 인스턴스 공유
        GoogleOAuthClient client = new GoogleOAuthClient(
                stubRestTemplate(GOOGLE_TOKEN_JSON, GOOGLE_USER_JSON), googleProperties());

        int threadCount = 30;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threadCount);
        AtomicInteger success = new AtomicInteger(0);
        AtomicInteger errors = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            int idx = i;
            new Thread(() -> {
                try {
                    start.await();
                    String token = client.getAccessToken("code-" + idx, "https://app.com/callback");
                    assertThat(token).isEqualTo("google-token");
                    success.incrementAndGet();
                } catch (Exception e) {
                    errors.incrementAndGet();
                } finally {
                    done.countDown();
                }
            }).start();
        }

        start.countDown();
        assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
        assertThat(errors.get()).isZero();
        assertThat(success.get()).isEqualTo(threadCount);
    }

    @Test
    @DisplayName("KakaoOAuthClient: 30 스레드 동시 getAccessToken() → 오류 없이 모두 완료")
    void concurrentKakaoTokenAcquisition() throws InterruptedException {
        KakaoOAuthClient client = new KakaoOAuthClient(
                stubRestTemplate(KAKAO_TOKEN_JSON, KAKAO_USER_JSON), kakaoProperties());

        int threadCount = 30;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threadCount);
        AtomicInteger success = new AtomicInteger(0);
        AtomicInteger errors = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            int idx = i;
            new Thread(() -> {
                try {
                    start.await();
                    String token = client.getAccessToken("code-" + idx, "https://app.com/callback");
                    assertThat(token).isEqualTo("kakao-token");
                    success.incrementAndGet();
                } catch (Exception e) {
                    errors.incrementAndGet();
                } finally {
                    done.countDown();
                }
            }).start();
        }

        start.countDown();
        assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
        assertThat(errors.get()).isZero();
        assertThat(success.get()).isEqualTo(threadCount);
    }

    // ── getUserInfo 동시성 ────────────────────────────────────────────────────

    @Test
    @DisplayName("GoogleOAuthClient: 30 스레드 동시 getUserInfo() → 응답 데이터 혼용 없음")
    void concurrentGoogleUserInfoFetch() throws InterruptedException {
        GoogleOAuthClient client = new GoogleOAuthClient(
                stubRestTemplate(GOOGLE_TOKEN_JSON, GOOGLE_USER_JSON), googleProperties());

        int threadCount = 30;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threadCount);
        AtomicInteger errors = new AtomicInteger(0);
        java.util.List<OAuthUserInfo> results = new java.util.concurrent.CopyOnWriteArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            new Thread(() -> {
                try {
                    start.await();
                    results.add(client.getUserInfo("google-token"));
                } catch (Exception e) {
                    errors.incrementAndGet();
                } finally {
                    done.countDown();
                }
            }).start();
        }

        start.countDown();
        assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
        assertThat(errors.get()).isZero();
        assertThat(results).hasSize(threadCount);
        results.forEach(u -> {
            assertThat(u.getProvider()).isEqualTo(OAuthProvider.GOOGLE);
            assertThat(u.getEmail()).isEqualTo("user@gmail.com");
            assertThat(u.getProviderId()).isEqualTo("g-123");
        });
    }

    @Test
    @DisplayName("KakaoOAuthClient: 30 스레드 동시 getUserInfo() → 응답 데이터 혼용 없음")
    void concurrentKakaoUserInfoFetch() throws InterruptedException {
        KakaoOAuthClient client = new KakaoOAuthClient(
                stubRestTemplate(KAKAO_TOKEN_JSON, KAKAO_USER_JSON), kakaoProperties());

        int threadCount = 30;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threadCount);
        AtomicInteger errors = new AtomicInteger(0);
        java.util.List<OAuthUserInfo> results = new java.util.concurrent.CopyOnWriteArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            new Thread(() -> {
                try {
                    start.await();
                    results.add(client.getUserInfo("kakao-token"));
                } catch (Exception e) {
                    errors.incrementAndGet();
                } finally {
                    done.countDown();
                }
            }).start();
        }

        start.countDown();
        assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
        assertThat(errors.get()).isZero();
        assertThat(results).hasSize(threadCount);
        results.forEach(u -> {
            assertThat(u.getProvider()).isEqualTo(OAuthProvider.KAKAO);
            assertThat(u.getEmail()).isEqualTo("user@kakao.com");
            assertThat(u.getProviderId()).isEqualTo("12345");
        });
    }

    // ── 혼합 동시 호출 ────────────────────────────────────────────────────────

    @Test
    @DisplayName("Google·Kakao 클라이언트 40 스레드 동시 전체 흐름 → 제공자 데이터 교차 오염 없음")
    void mixedConcurrentProviderCalls() throws InterruptedException {
        GoogleOAuthClient googleClient = new GoogleOAuthClient(
                stubRestTemplate(GOOGLE_TOKEN_JSON, GOOGLE_USER_JSON), googleProperties());
        KakaoOAuthClient kakaoClient = new KakaoOAuthClient(
                stubRestTemplate(KAKAO_TOKEN_JSON, KAKAO_USER_JSON), kakaoProperties());
        OAuthClientFactory factory = new OAuthClientFactory(List.of(googleClient, kakaoClient));

        int threadCount = 40;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threadCount);
        AtomicInteger errors = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            boolean useGoogle = (i % 2 == 0);
            new Thread(() -> {
                try {
                    start.await();
                    if (useGoogle) {
                        OAuthClient c = factory.getClient(OAuthProvider.GOOGLE);
                        OAuthUserInfo user = c.getUserInfo(c.getAccessToken("code", "uri"));
                        assertThat(user.getProvider()).isEqualTo(OAuthProvider.GOOGLE);
                        assertThat(user.getEmail()).isEqualTo("user@gmail.com");
                    } else {
                        OAuthClient c = factory.getClient(OAuthProvider.KAKAO);
                        OAuthUserInfo user = c.getUserInfo(c.getAccessToken("code", "uri"));
                        assertThat(user.getProvider()).isEqualTo(OAuthProvider.KAKAO);
                        assertThat(user.getEmail()).isEqualTo("user@kakao.com");
                    }
                } catch (AssertionError | Exception e) {
                    errors.incrementAndGet();
                } finally {
                    done.countDown();
                }
            }).start();
        }

        start.countDown();
        assertThat(done.await(15, TimeUnit.SECONDS)).isTrue();
        assertThat(errors.get()).isZero();
    }

    @Test
    @DisplayName("스레드 풀 기반 동시 전체 흐름: ExecutorService 20 worker → 예외 없이 완료")
    void executorServiceConcurrentFullFlow() throws Exception {
        GoogleOAuthClient googleClient = new GoogleOAuthClient(
                stubRestTemplate(GOOGLE_TOKEN_JSON, GOOGLE_USER_JSON), googleProperties());

        int workers = 20;
        int tasksPerWorker = 5;
        ExecutorService executor = Executors.newFixedThreadPool(workers);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger(0);

        java.util.List<Future<?>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < workers * tasksPerWorker; i++) {
            futures.add(executor.submit(() -> {
                try {
                    start.await();
                    String token = googleClient.getAccessToken("code", "uri");
                    OAuthUserInfo user = googleClient.getUserInfo(token);
                    assertThat(user.getProvider()).isEqualTo(OAuthProvider.GOOGLE);
                    success.incrementAndGet();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }

        start.countDown();
        for (Future<?> f : futures) {
            f.get(15, TimeUnit.SECONDS);
        }
        executor.shutdown();

        assertThat(success.get()).isEqualTo(workers * tasksPerWorker);
    }
}
