package com.qss.study.util;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
import com.qss.study.exception.BusinessException;
import com.qss.study.exception.CommonErrorCode;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;

/**
 * JwtToken工具类
 */
@Slf4j
public class JwtTokenUtil {
    /**
     * key（按照签名算法的字节长度设置key）
     */
    private static final String KEY = "0123456789_0123456789_0123456789";
    /**
     * 生成安全密钥 SignatureAlgorithm
     */
    private static final SecretKey SECRET_KEY = new SecretKeySpec(KEY.getBytes(), SignatureAlgorithm.HS256.getJcaName());
    /**
     * 过期时间，单位毫秒
     */
    private static final int INVALID_TIME = 24 * 60 * 60 * 1000;

    private JwtTokenUtil() {
    }

    /**
     * 生成token
     */
    public static String generateToken(JwtPayLoad jwtPayLoad) {
        DateTime expirationDate = DateUtil.offsetMillisecond(new Date(), INVALID_TIME);
        return Jwts.builder()
                .setClaims(BeanUtil.beanToMap(jwtPayLoad))
                .setSubject(jwtPayLoad.getUserAccount())
                .setIssuedAt(new Date())
                .setExpiration(expirationDate)
                .signWith(SECRET_KEY)
                .compact();
    }

    /**
     * 校验token是否正确
     *
     * @param token token
     * @return boolean
     */
    public static Boolean isTokenCorrect(String token) {
        try {
            getClaimsFromToken(token);
            return true;
        }catch (JwtException jwtException) {
            log.info("获取claim失败");
            return false;
        }
    }

    /**
     * 校验token是否失效
     * @param token token
     * @return boolean
     */
    public static Boolean isTokenExpired(String token) {
        try {
            Claims claims = getClaimsFromToken(token);
            final Date expiration = claims.getExpiration();
            return expiration.before(new Date());
        } catch (ExpiredJwtException expiredJwtException) {
            return true;
        }
    }

    /**
     * 根据token获取Claims
     *
     */
    public static Claims getClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 根据token获取JwtPayLoad部分
     * @param token token
     * @return JwtPayLoad
     */
    public static JwtPayLoad getJwtPayLoad(String token) {
        Claims claims = getClaimsFromToken(token);
        return BeanUtil.toBean(claims, JwtPayLoad.class);
    }

    /**
     * 校验token格式是否正确，获取不带Bear头的token
     * @param token token
     * @return token
     */
    public static String judgeTokenFormat(String token) {
        if (!token.startsWith("Bearer")) {
            throw BusinessException.of(CommonErrorCode.TOKEN_EXCEPTION, HttpStatus.UNAUTHORIZED, "token格式不正确，token请以Bearer开头，并且Bearer后边带一个空格");
        }
        try {
            token = token.substring("Bearer".length() + 1);
        } catch (StringIndexOutOfBoundsException e) {
            throw BusinessException.of(CommonErrorCode.TOKEN_EXCEPTION, HttpStatus.UNAUTHORIZED, "token格式不正确，token请以Bearer开头，并且Bearer后边带一个空格");
        }
        return token;
    }

    /**
     * 校验token是否正确及是否失效
     *
     * @param token token
     */
    public static void checkToken(String token) {
        //校验token是否正确
        boolean tokenCorrect = isTokenCorrect(token);
        if (!tokenCorrect) {
            throw BusinessException.of(CommonErrorCode.TOKEN_EXCEPTION, HttpStatus.UNAUTHORIZED, "请求token错误");
        }
        //校验token是否失效
        boolean tokenExpired = isTokenExpired(token);
        if (tokenExpired) {
            throw BusinessException.of(CommonErrorCode.TOKEN_EXCEPTION, HttpStatus.UNAUTHORIZED, "登录已过期，请重新登录");
        }
    }

    /**
     * 从token中获取登陆用户
     *
     * @param token token
     * @return 登陆用户
     */
    public static String getLoginUserAccountByToken(String token) {
        //校验token，错误则抛异常
        JwtTokenUtil.checkToken(token);

        //根据token获取JwtPayLoad部分
        JwtPayLoad jwtPayLoad = JwtTokenUtil.getJwtPayLoad(token);
        return jwtPayLoad.getUserAccount();
    }
}
