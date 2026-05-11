package io.github.ahnyeongjun.oauth;

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

/**
 * OAuth 부하 테스트.
 * 인메모리 HTTP 스텁을 사용하므로 네트워크 없이 라이브러리 자체 처리량을 측정.
 * CI에서도 통과하도록 처리량 임계값은 검증하지 않고 오류율 0% 만 단언.
 * 처리량 수치는 stdout으로 출력.
 */
@DisplayName("OAuth 부하 테스트")
class OAuthLoadTest {

    private static final String GOOGLE_TOKEN_JSON =
            "{\"access_token\":\"google-token\",\"token_type\":\"Bearer\"}";
    private static final String GOOGLE_USER_JSON =
            "{\"sub\":\"g-123\",\"email\":\"user@gmail.com\",\"name\":\"구글유저\"}";
    private static final String KAKAO_TOKEN_JSON =
            "{\"access_token\":\"kakao-token\",\"token_type\":\"bearer\"}";
    private static final String KAKAO_USER_JSON =
            "{\"id\":12345,\"kakao_account\":{\"email\":\"user@kakao.com\",\"profile\":{\"nickname\":\"카카오유저\"}}}";

    private static RestTemplate stubRestTemplate(String tokenJson, String userInfoJson) {
        RestTemplate rt = new RestTemplate();
        rt.setInterceptors(List.of((request, body, execution) -> {
            String json = request.getURI().toString().contains("token") ? tokenJson : userInfoJson;
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            return new ClientHttpResponse() {
                @Override public org.springframework.http.HttpStatusCode getStatusCode() { return HttpStatus.OK; }
                @Override public String getStatusText() { return "OK"; }
                @Override public HttpHeaders getHeaders() { return headers; }
                @Override public InputStream getBody() { return new ByteArrayInputStream(bytes); }
                @Override public void close() {}
            };
        }));
        return rt;
    }

    private static OAuthProperties googleProperties() {
        OAuthProperties props = new OAuthProperties();
        OAuthProperties.ProviderProperties p = new OAuthProperties.ProviderProperties();
        p.setClientId("g-id"); p.setClientSecret("g-sec");
        p.setTokenUrl("https://oauth2.googleapis.com/token");
        p.setUserInfoUrl("https://openidconnect.googleapis.com/v1/userinfo");
        props.setGoogle(p);
        return props;
    }

    private static OAuthProperties kakaoProperties() {
        OAuthProperties props = new OAuthProperties();
        OAuthProperties.ProviderProperties p = new OAuthProperties.ProviderProperties();
        p.setClientId("k-id"); p.setClientSecret("k-sec");
        p.setTokenUrl("https://kauth.kakao.com/oauth/token");
        p.setUserInfoUrl("https://kapi.kakao.com/v2/user/me");
        props.setKakao(p);
        return props;
    }

    // ── OAuthClientFactory 조회 처리량 ───────────────────────────────────────

    @Test
    @DisplayName("OAuthClientFactory 조회 처리량: 50 스레드 × 10,000 회 = 총 500,000 회")
    void factoryLookupThroughput() throws Exception {
        GoogleOAuthClient googleClient = new GoogleOAuthClient(
                stubRestTemplate(GOOGLE_TOKEN_JSON, GOOGLE_USER_JSON), googleProperties());
        KakaoOAuthClient kakaoClient = new KakaoOAuthClient(
                stubRestTemplate(KAKAO_TOKEN_JSON, KAKAO_USER_JSON), kakaoProperties());
        OAuthClientFactory factory = new OAuthClientFactory(List.of(googleClient, kakaoClient));

        int threads = 50;
        int iterations = 10_000;

        LoadResult result = runLoad("OAuthClientFactory 조회", threads, iterations, (threadIdx, iterIdx) -> {
            OAuthProvider target = (iterIdx % 2 == 0) ? OAuthProvider.GOOGLE : OAuthProvider.KAKAO;
            assertThat(factory.getClient(target)).isNotNull();
        });

        assertThat(result.errors()).isZero();
        assertThat(result.completed()).isEqualTo((long) threads * iterations);
    }

    // ── getAccessToken 처리량 ────────────────────────────────────────────────

    @Test
    @DisplayName("Google getAccessToken 처리량: 30 스레드 × 300 회 = 총 9,000 req")
    void googleTokenAcquisitionThroughput() throws Exception {
        GoogleOAuthClient client = new GoogleOAuthClient(
                stubRestTemplate(GOOGLE_TOKEN_JSON, GOOGLE_USER_JSON), googleProperties());

        LoadResult result = runLoad("Google getAccessToken", 30, 300, (threadIdx, iterIdx) -> {
            String token = client.getAccessToken("code-" + iterIdx, "https://app.com/cb");
            assertThat(token).isEqualTo("google-token");
        });

        assertThat(result.errors()).isZero();
        assertThat(result.completed()).isEqualTo(30L * 300);
    }

    @Test
    @DisplayName("Kakao getAccessToken 처리량: 30 스레드 × 300 회 = 총 9,000 req")
    void kakaoTokenAcquisitionThroughput() throws Exception {
        KakaoOAuthClient client = new KakaoOAuthClient(
                stubRestTemplate(KAKAO_TOKEN_JSON, KAKAO_USER_JSON), kakaoProperties());

        LoadResult result = runLoad("Kakao getAccessToken", 30, 300, (threadIdx, iterIdx) -> {
            String token = client.getAccessToken("code-" + iterIdx, "https://app.com/cb");
            assertThat(token).isEqualTo("kakao-token");
        });

        assertThat(result.errors()).isZero();
        assertThat(result.completed()).isEqualTo(30L * 300);
    }

    // ── getUserInfo 처리량 ────────────────────────────────────────────────────

    @Test
    @DisplayName("Google getUserInfo 처리량: 30 스레드 × 300 회 = 총 9,000 req")
    void googleUserInfoThroughput() throws Exception {
        GoogleOAuthClient client = new GoogleOAuthClient(
                stubRestTemplate(GOOGLE_TOKEN_JSON, GOOGLE_USER_JSON), googleProperties());

        LoadResult result = runLoad("Google getUserInfo", 30, 300, (threadIdx, iterIdx) -> {
            OAuthUserInfo user = client.getUserInfo("google-token");
            assertThat(user.getProvider()).isEqualTo(OAuthProvider.GOOGLE);
        });

        assertThat(result.errors()).isZero();
        assertThat(result.completed()).isEqualTo(30L * 300);
    }

    @Test
    @DisplayName("Kakao getUserInfo 처리량: 30 스레드 × 300 회 = 총 9,000 req")
    void kakaoUserInfoThroughput() throws Exception {
        KakaoOAuthClient client = new KakaoOAuthClient(
                stubRestTemplate(KAKAO_TOKEN_JSON, KAKAO_USER_JSON), kakaoProperties());

        LoadResult result = runLoad("Kakao getUserInfo", 30, 300, (threadIdx, iterIdx) -> {
            OAuthUserInfo user = client.getUserInfo("kakao-token");
            assertThat(user.getProvider()).isEqualTo(OAuthProvider.KAKAO);
        });

        assertThat(result.errors()).isZero();
        assertThat(result.completed()).isEqualTo(30L * 300);
    }

    // ── 전체 흐름(token + userInfo) 처리량 ──────────────────────────────────

    @Test
    @DisplayName("Google 전체 흐름 처리량: 20 스레드 × 200 회 = 총 4,000 HTTP 요청")
    void googleFullFlowThroughput() throws Exception {
        GoogleOAuthClient client = new GoogleOAuthClient(
                stubRestTemplate(GOOGLE_TOKEN_JSON, GOOGLE_USER_JSON), googleProperties());

        LoadResult result = runLoad("Google 전체 흐름", 20, 200, (threadIdx, iterIdx) -> {
            String token = client.getAccessToken("code-" + iterIdx, "https://app.com/cb");
            OAuthUserInfo user = client.getUserInfo(token);
            assertThat(user.getEmail()).isEqualTo("user@gmail.com");
        });

        assertThat(result.errors()).isZero();
        assertThat(result.completed()).isEqualTo(20L * 200);
    }

    @Test
    @DisplayName("Kakao 전체 흐름 처리량: 20 스레드 × 200 회 = 총 4,000 HTTP 요청")
    void kakaoFullFlowThroughput() throws Exception {
        KakaoOAuthClient client = new KakaoOAuthClient(
                stubRestTemplate(KAKAO_TOKEN_JSON, KAKAO_USER_JSON), kakaoProperties());

        LoadResult result = runLoad("Kakao 전체 흐름", 20, 200, (threadIdx, iterIdx) -> {
            String token = client.getAccessToken("code-" + iterIdx, "https://app.com/cb");
            OAuthUserInfo user = client.getUserInfo(token);
            assertThat(user.getEmail()).isEqualTo("user@kakao.com");
        });

        assertThat(result.errors()).isZero();
        assertThat(result.completed()).isEqualTo(20L * 200);
    }

    @Test
    @DisplayName("Google + Kakao 혼합 전체 흐름: 40 스레드 × 100 회, 두 provider 교차 부하")
    void mixedProviderFullFlowThroughput() throws Exception {
        GoogleOAuthClient googleClient = new GoogleOAuthClient(
                stubRestTemplate(GOOGLE_TOKEN_JSON, GOOGLE_USER_JSON), googleProperties());
        KakaoOAuthClient kakaoClient = new KakaoOAuthClient(
                stubRestTemplate(KAKAO_TOKEN_JSON, KAKAO_USER_JSON), kakaoProperties());
        OAuthClientFactory factory = new OAuthClientFactory(List.of(googleClient, kakaoClient));

        LoadResult result = runLoad("Google+Kakao 혼합 전체 흐름", 40, 100, (threadIdx, iterIdx) -> {
            if (threadIdx % 2 == 0) {
                GoogleOAuthClient c = (GoogleOAuthClient) factory.getClient(OAuthProvider.GOOGLE);
                OAuthUserInfo user = c.getUserInfo(c.getAccessToken("code", "uri"));
                assertThat(user.getProvider()).isEqualTo(OAuthProvider.GOOGLE);
            } else {
                KakaoOAuthClient c = (KakaoOAuthClient) factory.getClient(OAuthProvider.KAKAO);
                OAuthUserInfo user = c.getUserInfo(c.getAccessToken("code", "uri"));
                assertThat(user.getProvider()).isEqualTo(OAuthProvider.KAKAO);
            }
        });

        assertThat(result.errors()).isZero();
        assertThat(result.completed()).isEqualTo(40L * 100);
    }

    // ── 공통 부하 실행 유틸리티 ──────────────────────────────────────────────

    @FunctionalInterface
    private interface LoadTask {
        void run(int threadIdx, int iterIdx) throws Exception;
    }

    private record LoadResult(long completed, long errors, long elapsedMs) {
        double tps() {
            return elapsedMs > 0 ? (double) completed / elapsedMs * 1000 : 0;
        }
    }

    /**
     * 지정 스레드 수로 반복 작업을 수행하고 처리량을 측정.
     * 스레드는 start latch 신호와 동시에 출발해 처리량 측정의 공정성 보장.
     */
    private LoadResult runLoad(String label, int threads, int iterations, LoadTask task)
            throws InterruptedException, ExecutionException, TimeoutException {

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger(0);
        AtomicInteger errors = new AtomicInteger(0);

        List<Future<?>> futures = new java.util.ArrayList<>(threads);
        for (int t = 0; t < threads; t++) {
            int threadIdx = t;
            futures.add(executor.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < iterations; i++) {
                        try {
                            task.run(threadIdx, i);
                            success.incrementAndGet();
                        } catch (AssertionError | Exception e) {
                            errors.incrementAndGet();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }

        long wallStart = System.currentTimeMillis();
        start.countDown();
        for (Future<?> f : futures) {
            f.get(120, TimeUnit.SECONDS);
        }
        long elapsedMs = System.currentTimeMillis() - wallStart;
        executor.shutdown();

        LoadResult result = new LoadResult(success.get(), errors.get(), elapsedMs);
        System.out.printf("[부하] %-30s  완료=%,d  오류=%d  시간=%,dms  처리량=%.0f req/s%n",
                label, result.completed(), result.errors(), result.elapsedMs(), result.tps());
        return result;
    }
}
