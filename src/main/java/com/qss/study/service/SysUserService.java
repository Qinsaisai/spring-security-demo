package com.qss.study.service;

import cn.hutool.core.collection.CollUtil;
import cn.hutool.core.util.ObjectUtil;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.qss.study.dto.LoginUserInfo;
import com.qss.study.dto.RoleAuthority;
import com.qss.study.entity.SysRole;
import com.qss.study.entity.SysUser;
import com.qss.study.exception.BusinessException;
import com.qss.study.exception.CommonErrorCode;
import com.qss.study.mapper.SysUserMapper;
import com.qss.study.util.JwtTokenUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

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

    /**
     * 根据用户账号查询用户信息
     *
     * @param userAccount 用户账号
     * @return
     */
    public SysUser getByUserAccount(String userAccount) {
        return baseMapper.selectByUserAccount(userAccount);
    }

    /**
     * 设置SpringSecurityContext上下文，方便获取用户
     * todo: 此处查询当前用户信息可以设置redis缓存，避免频繁从数据库中查询操作
     *
     * @param userAccount 当前登录用户账号
     */
    public void setSpringSecurityContextAuthentication(String userAccount) {
        LoginUserInfo loginUserInfo=getLoginUserByAccount(userAccount);
        ArrayList<RoleAuthority> grantedAuthorities = CollUtil.newArrayList();
        if (ObjectUtil.isNotEmpty(loginUserInfo.getRoleList())) {
            loginUserInfo.getRoleList().forEach(sysRole -> {
                RoleAuthority roleAuthority = new RoleAuthority(sysRole.getRoleCode());
                grantedAuthorities.add(roleAuthority);
            });
        }
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(
                        loginUserInfo,
                        null,
                        grantedAuthorities);
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }

    /**
     * 根据用户账号获取用户登录信息
     * @param userAccount 用户账号
     * @return 用户登录信息
     */
    private LoginUserInfo getLoginUserByAccount(String userAccount) {
        SysUser sysUser=getByUserAccount(userAccount);
        LoginUserInfo loginUserInfo = new LoginUserInfo();
        BeanUtils.copyProperties(sysUser, loginUserInfo);
        List<SysRole> sysRoleList = sysRoleService.listRolesByUserAccount(userAccount);
        loginUserInfo.setRoleList(sysRoleList);
        return loginUserInfo;
    }

    /**
     * 获取当前登录用户信息
     *
     * @return 当前登录用户信息
     */
    public LoginUserInfo getLoginUser() {
        ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        assert requestAttributes != null;
        HttpServletRequest request = requestAttributes.getRequest();
        String token=request.getHeader("Authorization");
        log.info("token:{}",token);
        if (StringUtils.isBlank(token)){
            throw BusinessException.of(CommonErrorCode.TOKEN_EXCEPTION, HttpStatus.UNAUTHORIZED, "请求token为空，请携带token访问本接口");
        }
        //token不是以Bearer打头，则响应回格式不正确
        token= JwtTokenUtil.judgeTokenFormat(token);
        String userAccount=JwtTokenUtil.getLoginUserAccountByToken(token);
        return getLoginUserByAccount(userAccount);
    }
}
