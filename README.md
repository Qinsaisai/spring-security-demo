## 认证和鉴权
权限包括认证和鉴权两部分，spring-security-demo采用了SpringSecurity+JWT的权限验证。该例目前仅实现了认证部分，还未实现鉴权部分

### SpringSecurity+JWT
- SpringSecurity是Spring家族中的一个安全管理框架，其主要功能为认证、授权和攻击防护。在使用SpringSecurity时，首先在pom中引入依赖：
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```
- JSON Web Token (JWT)是一个开放标准(RFC 7519)，它定义了一种紧凑的、自包含的方式，用于作为JSON对象在各方之间安全地传输信息。该信息可以被验证和信任，因为它是数字签名的，
JWT的详细介绍可以参考[JWT官网](https://jwt.io/introduction/)。在使用JWT时，需要在pom中引入依赖：
```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.2</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.2</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.2</version>
    <scope>compile</scope>
</dependency>
```
spring-security-demo/src/main/java/com/qss/study/util/JwtTokenUtil是一个自定义[JWT工具类](#jwt工具类)，包含生成token、校验token是否正确、校验token是否失效、根据token获取用户信息等一系列方法。

### 登录流程
1. 自定义一个账号登录认证的Filter来拦截账号登录路径，这个Filter继承AbstractAuthenticationProcessingFilter，只需实现两部分，一个是RequestMatcher，指名拦截的Request类型和路径；另外就是从json body中提取出账号和密码提交给AuthenticationManager。
    
    ```java
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
    ```
2. 自定义认证管理类实现AuthenticationManager接口，所有的认证请求（比如login）都会通过提交一个Token给AuthenticationManager的authenticate()方法来实现。从上述工号登录认证Filter可以看到，
    我们提交UsernamePasswordAuthenticationToken给指定的自定义认证管理器LoginAuthenticationManager，自定义认证管理类如下所示：
    ```java
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
    ```
3. 所有的认证请求都会通过提交一个Token给AuthenticationManager的authenticate()方法来实现，但是，具体的校验动作其实并不是AuthenticationManager来做，而是会由AuthenticationManager将请求转发给其具体的实现类来做，即
认证的具体实现类AuthenticationProvider。所以自定义一个认证的具体实现类，在这个类中进行账号登录的具体校验动作，如下所示：
    ```java
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
    ```
    可以看到，AuthenticationProvider中的方法authenticate会返回一个Authentication对象，当通过认证后，这个对象往往会保存用户的详细信息。
4. 在AuthenticationProvider认证实现类中，我们主要是校验用户提供的认证信息和服务端保存的用户信息是否匹配以及服务端保存的用户信息是否冻结等，服务端用户信息的获取对应到SpringSecurity中
就是通过实现UserDetailsService并重写loadUserByUsername()方法来实现，如下所示：
    ```java
    @Slf4j
    @Service
    public class SysUserService extends ServiceImpl<SysUserMapper, SysUser> implements UserDetailsService {
        @Resource
        private SysRoleService sysRoleService;
    
        @Override
        public UserDetails loadUserByUsername(String s){
            //账号不存在
            SysUser sysUser = getByUserAccount(s);
            if (Objects.isNull(sysUser)) {
                throw new InternalAuthenticationServiceException("账号不存在，请检查");
            }
            //登录用户信息
            LoginUserInfo loginUserInfo = new LoginUserInfo();
            BeanUtils.copyProperties(sysUser, loginUserInfo);
            List<SysRole> sysRoleList = sysRoleService.listRolesByUserAccount(s);
            loginUserInfo.setRoleList(sysRoleList);
            log.info("JwtUserService中的loginUserInfo:{}",loginUserInfo);
            return loginUserInfo;
        }
        ......
    }
    ```
5. 自定义认证结果处理类，登录认证filter将token交给provider做校验，校验的结果无非两种，成功或者失败。对于这两种结果，我们只需要实现两个Handler接口，并set到登录认证Filter里面，Filter在收到Provider的处理结果后会回调这两个Handler的方法。
        - 先来看成功的情况，针对jwt认证的业务场景，登录成功需要返回给客户端一个token，所以成功的handler的实现类中需要调用[JWT工具类](#jwt工具类)生成token并添加到header头中，然后将认证成功的用户信息返回。
        ```java
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
        ```
        - 再来看失败的情况，登录失败直接返给客户端一个401响应即可。
        ```java
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
        ```

### 认证介绍
1. 认证可以证明你能登录系统，认证的过程即是校验token的过程。认证的核心是围绕JwtAuthenticationTokenFilter这个类来的，这个过滤器继承了OncePerRequestFilter类，在所有请求之前执行，
主要作用是接口在进入业务之前，通过token校验当前登录人的身份，添加登录上下文（SecurityContext），如下所示：
```java
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
```
此处为了避免当前用户如果一直在浏览客户端内容，但是由于token过期而被迫登出的情况，实现了token刷新的功能，即通过判断当前时间是否已超出了所设定的token失效时间的一半，如果已超出则重新生成token返回给客户端，前端则获取到新的token替换掉原来的token，从而避免上述情况的发生。

2. 匿名用户认证失败处理类，对于需要认证的接口如果访问时没有携带token，则应该返回给前端未认证的状态码401，如下所示：
```java
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
```

### 鉴权介绍

todo: 代码还未实现

在权限管理项目中，采用RBAC的权限模型，即对系统操作的各种权限不是直接授予具体的用户，而是在用户集合与权限集合之间建立一个角色集合。每一种角色对应一组相应的权限。一旦用户被分配了适当的角色后，该用户就拥有此角色的所有操作权限。
所以，鉴权可以证明你有系统的哪些权限，鉴权的过程是校验角色是否包含某些接口的权限。

权限管理项目对于接口权限控制的逻辑如下：
1. 将需要鉴权的接口维护到接口列表中，未添加到数据表sys_api中的接口默认所有角色都可以访问；
2. 给接口列表中的接口授予角色权限，即哪种角色可以访问该接口，如果接口未授权那么任何角色都可以访问；
3. 接口请求通过自定义权限资源过滤器MyFilterInvocationSecurityMetadataSource，来加载这个接口访问时所需要的具体权限，即返回这个url对应的角色权限。这个自定义权限资源过滤器
实现了权限资源接口FilterInvocationSecurityMetadataSource，如下所示：
```java
@Slf4j
@Component
public class MyFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
    @Resource
    private SysRoleApiService sysRoleApiService;

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    public Collection<ConfigAttribute> getAttributes(Object o) {
        String requestUrl = ((FilterInvocation) o).getRequestUrl();
        //不需要登录之后访问的接口，返回null即可，返回null则不会进入之后的decide方法，且所有人包括未携带token的匿名用户都可以访问，
        for (String ignoreUrl : SpringSecurityConstant.NONE_SECURITY_URL_PATTERNS) {
            if (ignoreUrl.contains("**")) {
                ignoreUrl = ignoreUrl.substring(0, ignoreUrl.indexOf("*"));
            }
            if (requestUrl.contains(ignoreUrl) || ignoreUrl.contains(requestUrl)) {
                return Collections.emptyList();
            }
        }
        // remove parameters
        if (requestUrl.contains(CommonConstants.URL_PARAMETER)) {
            requestUrl = requestUrl.substring(0, requestUrl.indexOf(CommonConstants.URL_PARAMETER));
        }
        String method = ((FilterInvocation) o).getHttpRequest().getMethod();
        //查询已授权的接口权限列表
        List<ApiRole> roleApiList = sysRoleApiService.getAllRoleApi();
        for (ApiRole apiRole : roleApiList) {
            String apiPath = apiRole.getApiPath();
            List<String> roleCodeList = apiRole.getRoleCodeList();
            String apiMethod = apiRole.getApiMethod();
            if (antPathMatcher.match(apiPath, requestUrl) && !roleCodeList.isEmpty() && method.equals(apiMethod)) {
                List<String> roleList = apiRole.getRoleCodeList();
                int size = roleList.size();
                String[] values = new String[size];
                for (int i = 0; i < size; i++) {
                    values[i] = roleList.get(i);
                }
                return SecurityConfig.createList(values);
            }
        }
        //没有匹配上的资源，都是登录访问,给定一个角色标识，便于在decide中处理。该角色标识并不存在于角色表中，只是为了在decide中处理需要登录才能访问的情况。
        return SecurityConfig.createList(ROLE_LOGIN);
    }

    /**
     * 此处方法如果做了实现，返回了定义的权限资源列表，
     * Spring Security会在启动时校验每个ConfigAttribute是否配置正确，
     * 如果不需要校验，这里实现方法，方法体直接返回null即可。
     **/
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return Collections.emptyList();
    }

    /**
     * 方法返回类对象是否支持校验，
     * web项目一般使用FilterInvocation来判断，或者直接返回true
     **/
    @Override
    public boolean supports(Class<?> aClass) {
        return FilterInvocation.class.isAssignableFrom(aClass);
    }
}
```
4. 有了权限资源(MyFilterInvocationSecurityMetadataSource)，知道了当前访问的url需要的具体权限，接下来就是决策当前的访问是否能通过权限验证了,
所以自定义一个权限决策管理器MyAccessDecisionManager，来判断当前用户是否具有当前请求接口需要的角色权限，自定义权限决策管理器如下所示：
```java
@Slf4j
@Component
public class MyAccessDecisionManager implements AccessDecisionManager {
    /**
     * 取当前用户的权限与这次请求的这个url需要的权限作对比，决定是否放行
     * auth 包含了当前的用户信息，包括拥有的权限,即之前UserDetailsService登录时候存储的用户对象
     * object 就是FilterInvocation对象，可以得到request等web资源。
     * cas 是本次访问需要的权限。即上一步的 MyFilterInvocationSecurityMetadataSource 中查询核对得到的权限列表
     **/
    @Override
    public void decide(Authentication auth, Object object, Collection<ConfigAttribute> cas) {
        for (ConfigAttribute configAttribute : cas) {
            //当前请求需要的权限
            String needRole = configAttribute.getAttribute();
            if (ROLE_LOGIN.equals(needRole)) {
                if (auth instanceof AnonymousAuthenticationToken) {
                    throw new AccessDeniedException("未登录");
                } else {
                    return;
                }
            }
            //当前用户所具有的权限
            Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
            for (GrantedAuthority authority : authorities) {
                if (authority.getAuthority().equals(needRole)) {
                    return;
                }
            }
        }
        throw new AccessDeniedException("权限不足!");
    }

    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}
```
5. 如果当前用户没有当前请求接口所需要的角色，那么该接口不允许访问，鉴权失败，需要自定义一个鉴权失败处理器，以便响应给前端禁止访问的状态码403。
该自定义鉴权失败处理器如下所示：
```java
@Slf4j
@Component
public class MyAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException {
        //认证过的用户访问无权限资源时的异常处理（当访问接口没有权限时，自定义的返回结果）
        ResponseUtil.responseExceptionError(response, CommonErrorCode.FORBIDDEN, HttpStatus.FORBIDDEN, AuthExceptionEnum.NO_AUTHORITY.getMessage(), request.getRequestURI());
    }
}
```

### SpringSecurity配置
整个登录和用户认证鉴权所需要的处理已完成，现在需要把SpringSecurity集成到我们的SpringBoot项目中去，所以我们需要定义SpringSecurity配置类SpringSecurityConfig，继承
WebSecurityConfigurerAdapter，进行个性化配置，如下所示：
```java
@Slf4j
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
    @Resource
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    @Resource
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;
    @Resource
    private MyFilterInvocationSecurityMetadataSource myFilterInvocationSecurityMetadataSource;
    @Resource
    private MyAccessDecisionManager myAccessDecisionManager;
    @Resource
    private MyAccessDeniedHandler myAccessDeniedHandler;

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
        for (String notAuthResource : SpringSecurityConstant.NONE_SECURITY_URL_PATTERNS) {
            httpSecurity.authorizeRequests().antMatchers(notAuthResource).permitAll();
        }
        //其余的都需授权访问
        httpSecurity.authorizeRequests().anyRequest().authenticated();
        //未授权时访问需授权的资源端点
        httpSecurity.exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint);
        //用户访问没有授权资源
        httpSecurity.exceptionHandling().accessDeniedHandler(myAccessDeniedHandler);
        //接口权限控制
        httpSecurity.authorizeRequests()
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O o) {
                        o.setSecurityMetadataSource(myFilterInvocationSecurityMetadataSource);
                        o.setAccessDecisionManager(myAccessDecisionManager);
                        return o;
                    }
                });
        //全局不创建session
        httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        //禁用页面缓存，返回的都是json
        httpSecurity.headers()
                .frameOptions().disable()
                .cacheControl();
    }
}
```

### JWT工具类
在spring-security-demo/src/main/java/com/qss/study/util下自定义了一个Jwt工具类JwtTokenUtil，定义了一系列与jwt token相关的方法，如下所示为其中几个方法：

1. 生成token
```java
/**
 * key（按照签名算法的字节长度设置key）
 */
private static final String KEY = "0123456789_0123456789_0123456789";
/**
 * 生成安全密钥
 */
private static final SecretKey SECRET_KEY = new SecretKeySpec(KEY.getBytes(), SignatureAlgorithm.HS256.getJcaName());
/**
 * 过期时间，单位毫秒
 */
private static final int INVALID_TIME = 24 * 60 * 60 * 1000;

public static String generateToken(JwtPayLoad jwtPayLoad) {
        DateTime expirationDate = DateUtil.offsetMillisecond(new Date(), INVALID_TIME);
        return Jwts.builder()
                .setClaims(BeanUtil.beanToMap(jwtPayLoad))
                .setSubject(jwtPayLoad.getLoginUserInfo().getUserAccount())
                .setIssuedAt(new Date())
                .setExpiration(expirationDate)
                .signWith(SECRET_KEY)
                .compact();
    }
```
注意：此处设置了token失效时间为24小时，采用HS256生成安全密钥，你可以根据需要修改token过期时间、KEY以及生成安全密钥的方法。

2. 校验token是否正确
```java
public static Boolean isTokenCorrect(String token) {
        try {
            getClaimsFromToken(token);
            return true;
        }catch (JwtException jwtException) {
            log.info("获取claim失败");
            return false;
        }
    }
```
3. 校验token是否失效
```java
public static Boolean isTokenExpired(String token) {
        try {
            Claims claims = getClaimsFromToken(token);
            final Date expiration = claims.getExpiration();
            return expiration.before(new Date());
        } catch (ExpiredJwtException expiredJwtException) {
            return true;
        }
    }
```
4. 从token中获取登陆用户
```java
public static LoginUserInfo getLoginUserByToken(String token) {
        //校验token，错误则抛异常
        JwtTokenUtil.checkToken(token);
        //根据token获取JwtPayLoad部分
        JwtPayLoad jwtPayLoad = JwtTokenUtil.getJwtPayLoad(token);
        return jwtPayLoad.getLoginUserInfo();
    }
```
