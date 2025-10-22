package com.flp.secure.client.controllers;

import com.flp.secure.client.config.NoOAuth2Config;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@Import(NoOAuth2Config.class)
@ActiveProfiles("test")
@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
public class ClientControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void welcomeEndPointReturns200Unauthenticated() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/welcome")
                        .with(SecurityMockMvcRequestPostProcessors.oauth2Login()))
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful());
    }
}
