package io.github.shirohoo.samples.security.jwt

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class JWTSecurityApplication

fun main(args: Array<String>) {
    runApplication<JWTSecurityApplication>(*args)
}
