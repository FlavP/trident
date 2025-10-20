package com.flp.secure.client.controllers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.client.RestClient;

import static org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver.clientRegistrationId;

@Controller
public class ClientController {
    @Value("${oauth2-config.init-auth-path}")
    private String initAuthPath;
    @Value("${oauth2-config.resource-url}")
    private String resourceUrl;

    private final RestClient restClient;

    public ClientController(RestClient r) {
        this.restClient = r;
    }

    @GetMapping("/welcome")
    public String welcome(Model model, OAuth2AuthenticationToken token) {
        model.addAttribute("userName", token.getPrincipal().getName());
        return "welcome";
    }

    @PostMapping("welcome")
    public String postWelcome(Model model, OAuth2AuthenticationToken token) {
        model.addAttribute("userName", token.getPrincipal().getName());

        String secret = this.restClient
                .get()
                .uri(resourceUrl)
                .attributes(clientRegistrationId("my-auth-server"))
                .retrieve()
                .body(String.class);

        model.addAttribute("secretInfo", secret);

        return "welcome";
    }

    @GetMapping("/loginpage")
    public String login(Model model) {
        model.addAttribute("initAuthPath", initAuthPath);
        return "loginpage";
    }
}
