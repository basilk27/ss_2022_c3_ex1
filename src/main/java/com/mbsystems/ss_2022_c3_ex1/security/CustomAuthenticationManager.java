package com.mbsystems.ss_2022_c3_ex1.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationManager implements AuthenticationManager {

    private final CustomeAuthenticationProvider customeAuthenticationProvider;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (customeAuthenticationProvider.supports(authentication.getClass())) {
            return customeAuthenticationProvider.authenticate(authentication);
        }

        throw new BadCredentialsException("Invalid Credentials");
    }
}
