package threethreeohoh.rainfall.user.controller;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class KakaoLoginController {

    @GetMapping("/login/success")
    public String loginSuccess(OAuth2AuthenticationToken authentication) {
        return "로그인 정보: " + authentication.getPrincipal().getAttributes();
    }

}
