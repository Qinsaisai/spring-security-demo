package com.qss.study.handler;

import com.qss.study.dto.LoginUserInfo;
import com.qss.study.util.JwtPayLoad;
import com.qss.study.util.JwtTokenUtil;
import com.qss.study.util.ResponseUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录成功后的处理结果，header中增加token且返回用户信息
 */
@Slf4j
@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("登录成功后的处理结果");
        LoginUserInfo loginUserInfo=(LoginUserInfo) authentication.getPrincipal();

        JwtPayLoad jwtPayLoad=new JwtPayLoad(loginUserInfo.getUserAccount());
        String token= JwtTokenUtil.generateToken(jwtPayLoad);
        response.addHeader("Authorization", token);
        String code="success";
        String message="success";
        int status= HttpStatus.OK.value();
        Object data=loginUserInfo;
        ResponseUtil.ResponseResult(response, code, message, status, data);
    }
}
