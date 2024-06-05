package com.example.springoauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

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
