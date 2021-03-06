package com.qss.study.handler;

import com.qss.study.util.ResponseUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录失败后的处理结果
 */
@Slf4j
@Component
public class LoginFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        log.info("登录失败后的处理结果:{}",e.getMessage());
        String code="fail";
        String message="登录失败";
        int status=HttpStatus.UNAUTHORIZED.value();
        Object data=null;
        ResponseUtil.ResponseResult(httpServletResponse, code, message, status, data);
    }
}
