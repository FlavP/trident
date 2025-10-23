package com.flp.secure.resourceserver.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@SpringBootTest
@AutoConfigureMockMvc
public class ResourceServerControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void returns200WithAuthorities() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/secret")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(() -> "SCOPE_read:secret")))
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful());
    }

    @Test
    void returns4xxWithWrongAuthorities() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/secret")
                        .with(SecurityMockMvcRequestPostProcessors.jwt()
                                .authorities(() -> "fake:scope")))
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }
}
