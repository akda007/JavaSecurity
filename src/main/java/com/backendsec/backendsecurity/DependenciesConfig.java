package com.backendsec.backendsecurity;

import com.backendsec.backendsecurity.impl.*;
import com.backendsec.backendsecurity.services.HashService;
import com.backendsec.backendsecurity.services.KeyService;
import com.backendsec.backendsecurity.services.SignatureService;
import com.backendsec.backendsecurity.services.UserAuth;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DependenciesConfig {
    @Bean
    @Scope("singleton")
    public SignatureService signatureService() {
        return new RS256SignatureService();
    }

    @Bean
    @Scope("singleton")
    public KeyService keyService() {
        return new RSAKeyService();
    }
    @Bean
    @Scope("singleton")
    public HashService hashService() {
        return new SHA256HashService();
    }

    @Bean
    @Scope()
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Scope()
    public UserAuth userAuth() {
        return new DefaultUserAuthService();
    }
}
