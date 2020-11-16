package com.qss.study.filter;

import com.alibaba.fastjson.JSON;
import com.qss.study.handler.LoginFailureHandler;
import com.qss.study.handler.LoginSuccessHandler;
import com.qss.study.service.LoginAuthenticationManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;
import com.alibaba.fastjson.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 普通账号密码登录过滤器
 */
@Slf4j
@Component
public class MyUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public MyUsernamePasswordAuthenticationFilter(LoginAuthenticationManager loginAuthenticationManager,
                                                  LoginSuccessHandler loginSuccessHandler,
                                                  LoginFailureHandler loginFailureHandler) {
        //拦截url为 "/login" 的POST请求
        super(new AntPathRequestMatcher("/login", "POST"));
        this.setAuthenticationManager(loginAuthenticationManager);
        this.setAuthenticationSuccessHandler(loginSuccessHandler);
        this.setAuthenticationFailureHandler(loginFailureHandler);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException {
        //从json中获取username和password
        String body = StreamUtils.copyToString(request.getInputStream(), StandardCharsets.UTF_8);
        String username = null;
        String password = null;
        if(StringUtils.hasText(body)) {
            JSONObject jsonObj = JSON.parseObject(body);
            username = jsonObj.getString("account");
            password = jsonObj.getString("password");
        }
        if (username == null){
            username = "";
        }
        if (password == null){
            password = "";
        }
        username = username.trim();
        //封装到token中提交
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                username, password);

        return this.getAuthenticationManager().authenticate(authRequest);
    }
}
