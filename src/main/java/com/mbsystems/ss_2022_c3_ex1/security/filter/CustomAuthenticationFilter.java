package com.mbsystems.ss_2022_c3_ex1.security.filter;

import com.mbsystems.ss_2022_c3_ex1.security.CustomAuthentication;
import com.mbsystems.ss_2022_c3_ex1.security.CustomAuthenticationManager;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private final CustomAuthenticationManager customAuthenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // 1- create an authentication object which is not yet authenticated
        // 2- delegate the authentication object to the manager
        // 3- get back the authentication from the manager
        // 4- if the object is authenticated then send request to the next filter in the chain

        String key = String.valueOf(request.getHeader("key"));

        var customAuthentication = new CustomAuthentication(false, key);

        var authentication = this.customAuthenticationManager.authenticate(customAuthentication);

        if (authentication.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(authentication);

            filterChain.doFilter(request, response);        //note for bmk - only when authentication worked
        }
    }
}
