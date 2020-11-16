package com.qss.study.filter;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.http.ContentType;
import com.alibaba.fastjson.JSON;
import com.qss.study.service.SysUserService;
import com.qss.study.util.JwtPayLoad;
import com.qss.study.util.JwtTokenUtil;
import com.qss.study.util.ResponseUtil;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT登录授权过滤器
 * 这个过滤器，在所有请求之前，也在spring security filters之前
 * 这个过滤器的作用是：接口在进业务之前，添加登录上下文（SecurityContext）
 * 因为现在通过token来校验当前的登录人的身份，所以在进业务之前要给当前登录人设置登录状态
 */
@Slf4j
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    @Resource
    private SysUserService sysUserService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        log.info("无论是谁都要先从我这过滴");
        // 1.如果当前请求带了token，判断token时效性，并获取当前登录用户信息
        String userAccount = null;
        try {
            String token = request.getHeader("Authorization");
            if (StrUtil.isNotEmpty(token)){
                //token不是以Bearer打头，则响应回格式不正确
                token = JwtTokenUtil.judgeTokenFormat(token);
            }
            if (StrUtil.isNotEmpty(token)) {
                userAccount = JwtTokenUtil.getLoginUserAccountByToken(token);
                //刷新token,如果当前时间已超过所定义的过期时间的一半，则生成新的token
                Claims claims = JwtTokenUtil.getClaimsFromToken(token);
                Date expiration = claims.getExpiration();
                Date issueAt = claims.getIssuedAt();
                long time = expiration.getTime() - issueAt.getTime();
                long now = expiration.getTime() - (new Date()).getTime();
                if (now < time / 2) {
                    //构造jwtPayLoad
                    JwtPayLoad jwtPayLoad = new JwtPayLoad(userAccount);
                    String newToken = JwtTokenUtil.generateToken(jwtPayLoad);
                    response.addHeader("Authorization", newToken);
                }
            }
        } catch (Exception e) {
            //token过期或者token失效的情况，响应给前端
            String code="fail";
            String message="访问"+request.getRequestURI()+"时token错误";
            int status=HttpStatus.UNAUTHORIZED.value();
            Object data=null;
            ResponseUtil.ResponseResult(response, code, message, status, data);
            return;
        }

        // 2.如果当前登录用户不为空，就设置spring security上下文
        if (ObjectUtil.isNotNull(userAccount)) {
            sysUserService.setSpringSecurityContextAuthentication(userAccount);
        }

        // 3.其他情况放开过滤
        filterChain.doFilter(request, response);
    }
}
