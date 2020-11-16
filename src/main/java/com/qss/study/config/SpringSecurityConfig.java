package com.qss.study.config;

import com.qss.study.filter.JwtAuthenticationTokenFilter;
import com.qss.study.handler.JwtAuthenticationEntryPoint;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.annotation.Resource;

/**
 * SpringSecurity配置
 */
@Slf4j
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    @Resource
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    @Resource
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

    /**
     * 开启跨域访问拦截器
     */
    @Bean
    public CorsFilter corsFilter() {
        //1. 添加Cors配置信息
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        //放行哪些原始域
        corsConfiguration.addAllowedOrigin("*");
        //放行哪些原始域（头部信息）
        corsConfiguration.addAllowedHeader("*");
        //放行哪些原始域（请求方法）
        corsConfiguration.addAllowedMethod("*");
        //2. 添加映射路径
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        //3. 返回新的CorsFilter
        return new CorsFilter(source);
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {

        //开启模拟请求，比如API POST测试工具的测试，不开启时，API POST为报403错误
        httpSecurity.csrf().disable();

        //开启跨域访问
        httpSecurity.cors();

        httpSecurity.formLogin().disable();

        //不使用默认退出，自定义退出
        httpSecurity.logout().disable();

        //前置token过滤器
        httpSecurity.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);

        //放开一些接口的权限校验
        httpSecurity.authorizeRequests().antMatchers("/login","/logout").permitAll();

        //其余的都需授权访问
        httpSecurity.authorizeRequests().anyRequest().authenticated();

        //未授权时访问需授权的资源端点，即未登录异常
        httpSecurity.exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint);

        //全局不创建session
        httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        //禁用页面缓存，返回的都是json
        httpSecurity.headers()
                .frameOptions().disable()
                .cacheControl();
    }

}
