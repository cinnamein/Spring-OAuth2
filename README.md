# springBoot에서 oauth2를 사용한 로그인 구현

## 의존성 추가

_org.springframework.boot:spring-boot-starter-oauth2-client_ 를 통해 스프링 시큐리티에서 기본적으로 제공하는 OAuth2.0 프로토콜을 사용한다.

```gradle
implementation 'org.springframework.boot:spring-boot-starter-oauth2-client'
```

## SecurityConfig

보안 구성 및 인증/인가 설정을 구성한다. 본 코드는 구글을 기준으로 작성되었다.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/oauth/**").permitAll()
                        .anyRequest().permitAll()
                )
                .oauth2Login(withDefaults());

        return http.build();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
    }

    @Bean
    public ClientRegistration googleClientRegistration() {
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("access_type", "offline");
        return ClientRegistration
                .withRegistrationId("google")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/oauth/redirect/google")
                .scope("profile", "email")
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent")
                .tokenUri("https://www.googleapis.com/oauth2/v4/token")
                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                .clientName("Google")
                .build();
    }
}
```

- Registration ID: 클라이언트 등록을 식별하는 고유한 식별자
- Client ID: 클라이언트 애플리케이션의 id
- Client Secret: 클라이언트 애플리케이션의 secret key
- Client Authentication Method: 클라이언트 인증 방법
- Authorization Grant Type: 클라이언트가 액세스 토큰을 요청할 때 사용할 인가 유형
- Redirect URI: 사용자 인증 후에 리디렉션되는 URI
- Scope: 클라이언트가 요청할 수 있는 권한 범위
- Authorization URI: 인가 코드를 받기 위한 엔드포인트 URI
- Token URI: 액세스 토큰을 요청하기 위한 엔드포인트 URI
- User Info URI: 사용자 정보 엔드포인트 URI
- User Name Attribute Name: 사용자의 고유 식별자 속성 이름
- JWK Set URI: Json Web Key Set 엔드포인트 URI
- Client Name: 클라이언트의 이름 또는 제목

## OAuthController

엔드포인트의 실제 동작과 관련된 로직을 Service에 구현하기 위해 매핑해준다.

```java
@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final OAuthService oauthService;

    @GetMapping("/redirect/{registrationId}")
    public void loadUser(@RequestParam String code, @PathVariable String registrationId) {
        oauthService.socialLogin(code, registrationId);
    }
}
```

로그인이 정상적으로 이루어졌다면 code에는 인증 코드가, registrationId에는 로그인을 지원해준 서비스가 넘어오게 된다. 해당 코드에서는 google을 받아오게 된다.

## OAuthService

실질적인 동작 부분을 구현한다.

```java
@Service
@RequiredArgsConstructor
public class OAuthService {

    private final RestTemplate restTemplate = new RestTemplate();
    private final ClientRegistration googleClientRegistration;

    public void socialLogin(String code, String registrationId) {
        JsonNode tokens = getToken(code, registrationId);
        String accessToken = tokens.get("access_token").asText();
        String refreshToken = tokens.get("refresh_token").asText();

        JsonNode userInfo = getUserResource(accessToken);
    }

    private JsonNode getToken(String code, String registrationId) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("prompt", "consent");
        params.add("client_id", googleClientRegistration.getClientId());
        params.add("client_secret", googleClientRegistration.getClientSecret());
        params.add("redirect_uri", googleClientRegistration.getRedirectUri());
        params.add("code", code);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);

        String tokenUri = googleClientRegistration.getProviderDetails().getTokenUri();
        ResponseEntity<JsonNode> response = restTemplate.exchange(
                tokenUri,
                HttpMethod.POST,
                entity,
                JsonNode.class);
        return response.getBody();
    }

    private JsonNode getUserResource(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);

        HttpEntity entity = new HttpEntity(headers);

        String userInfoUri = googleClientRegistration.getProviderDetails().getUserInfoEndpoint().getUri();

        return restTemplate.exchange(userInfoUri,
                HttpMethod.GET,
                entity,
                JsonNode.class).getBody();
    }
}
```

- getToken: access token과 refresh token을 Json객체로 받아온다.
- getUserResource: 유저 정보를 Json 객체로 받아온다.