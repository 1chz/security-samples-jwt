package io.github.shirohoo.samples.security.jwt

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.context.annotation.Import
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@Import(SecurityConfig::class)
@WebMvcTest(SecurityController::class)
class SecurityControllerTests(@Autowired val mvc: MockMvc) {
    @Test
    fun `토큰이 유효하다면 Hello, username! 이라고 응답합니다`() {
        val result = mvc.perform(post("/token").with(httpBasic("username", "password")))
            .andExpect(status().isOk)
            .andReturn()

        val token = result.response.contentAsString

        mvc.perform(
            get("/").header("Authorization", "Bearer $token")
        ).andExpect(content().string("Hello, username!"))
    }

    @Test
    fun `잘못된 자격증명일 경우 401을 반환합니다`() {
        mvc.perform(get("/"))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun `토큰이 없다면 401을 반환합니다`() {
        mvc.perform(get("/token"))
            .andExpect(status().isUnauthorized)
    }
}