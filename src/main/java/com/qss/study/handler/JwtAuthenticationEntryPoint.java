package com.qss.study.handler;

import com.qss.study.util.ResponseUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;

/**
 * 认证失败处理类，返回401
 * 未认证用户访问授权资源端点时的异常处理（匿名用户访问授权接口时的自定义返回结果）
 */
@Slf4j
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException {
        log.info("我没有带token呀");
        //响应给前端无权限访问本接口（没有携带token）
        String code="fail";
        String message=request.getRequestURI()+"时,请求token为空，请携带token访问本接口";
        int status=HttpStatus.UNAUTHORIZED.value();
        Object data=null;
        ResponseUtil.ResponseResult(response, code, message, status, data);
    }
}
