package io.github.shirohoo.samples.security.jwt

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

@RestController
class SecurityController(val jwtEncoder: JwtEncoder) {
    @GetMapping("/")
    fun hello(auth: Authentication): String {
        return "Hello, ${auth.name}!"
    }

    @PostMapping("/token")
    fun token(auth: Authentication): String {
        val now = Instant.now()
        val claims = JwtClaimsSet.builder()
            .issuer("https://example.com")
            .issuedAt(now)
            .expiresAt(now.plusSeconds(300))
            .subject(auth.name)
            .claim("scope", "demo:read")
            .build()

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).tokenValue
    }
}