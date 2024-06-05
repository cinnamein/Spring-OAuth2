package com.example.springoauth2;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

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
