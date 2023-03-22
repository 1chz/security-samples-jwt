package io.github.shirohoo.samples.security.jwt

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.userdetails.User
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

@Configuration
class SecurityConfig {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain = http
        .authorizeHttpRequests { it.anyRequest().authenticated() }
        .csrf { it.ignoringRequestMatchers("/token") }
        .httpBasic(Customizer.withDefaults())
        .oauth2ResourceServer { it.jwt() }
        .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
        .exceptionHandling {
            it.authenticationEntryPoint(BearerTokenAuthenticationEntryPoint())
                .accessDeniedHandler(BearerTokenAccessDeniedHandler())
        }.build()

    @Bean
    fun imMemoryUsers() = User
        .withUsername("username")
        .password("{noop}password")
        .authorities("demo:read")
        .build()
        .let { InMemoryUserDetailsManager(it) }

    @Bean
    fun jwtDecoder(@Value("\${security.key.public}") rsaPublicKey: RSAPublicKey): JwtDecoder = NimbusJwtDecoder.withPublicKey(rsaPublicKey).build()

    @Bean
    fun jwtEncoder(
        @Value("\${security.key.public}") rsaPublicKey: RSAPublicKey,
        @Value("\${security.key.private}") rsaPrivateKey: RSAPrivateKey
    ) = RSAKey.Builder(rsaPublicKey).privateKey(rsaPrivateKey).build()
        .let { NimbusJwtEncoder(ImmutableJWKSet(JWKSet(it))) }
}