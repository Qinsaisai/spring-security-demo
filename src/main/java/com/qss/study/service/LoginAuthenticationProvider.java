package com.qss.study.service;

import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Slf4j
@Component
public class LoginAuthenticationProvider implements AuthenticationProvider {
    @Resource
    private SysUserService sysUserService;

    private static final PasswordEncoder ENCODER = new BCryptPasswordEncoder();

    @Override
    public Authentication authenticate(Authentication authentication) {
        log.info("authentication1:{}",authentication);
        String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
        String password = (String) authentication.getCredentials();
        if(StringUtils.isBlank(username) || StringUtils.isBlank(password)){
            throw new InternalAuthenticationServiceException("账号或密码为空，请检查");
        }
        UserDetails loginUserInfo= sysUserService.loadUserByUsername(username);
        log.info("loginUserInfo1:{}",loginUserInfo);
        //验证密码是否匹配
        if (!ENCODER.matches(password, loginUserInfo.getPassword())) {
            throw new InternalAuthenticationServiceException("密码错误，请重新输入密码");
        }
        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(loginUserInfo, null, loginUserInfo.getAuthorities());
        result.setDetails(authentication.getDetails());
        return result;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }
}
