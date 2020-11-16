package com.qss.study.dto;

import com.qss.study.entity.SysRole;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Data
public class LoginUserInfo implements UserDetails {
    /**
     * 主键ID
     */
    private Integer id;
    /**
     * 用户名
     */
    private String name;
    /**
     * 用户账号
     */
    private String userAccount;
    /**
     * 密码
     */
    private String password;
    /**
     * 邮箱
     */
    private String email;
    /**
     * 角色列表
     */
    private List<SysRole> roleList;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorityList = new ArrayList<>();
        for (SysRole sysRole:roleList){
            authorityList.add(new SimpleGrantedAuthority(sysRole.getRoleCode()));
        }
        return authorityList;
    }

    @Override
    public String getUsername() {
        return this.userAccount;
    }

    @Override
    public String getPassword(){
        return this.password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
