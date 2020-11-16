package com.qss.study.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.Objects;

@Component
public class LoginAuthenticationManager implements AuthenticationManager {
    @Resource
    private LoginAuthenticationProvider loginAuthenticationProvider;

    public LoginAuthenticationManager(LoginAuthenticationProvider loginAuthenticationProvider){
        this.loginAuthenticationProvider=loginAuthenticationProvider;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        Authentication result = loginAuthenticationProvider.authenticate(authentication);
        if (Objects.nonNull(result)) {
            return result;
        }
        throw new ProviderNotFoundException("Authentication failed!");
    }
}
