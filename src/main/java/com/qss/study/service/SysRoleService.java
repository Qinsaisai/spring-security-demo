package com.qss.study.service;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.qss.study.entity.SysRole;
import com.qss.study.mapper.SysRoleMapper;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SysRoleService extends ServiceImpl<SysRoleMapper, SysRole> {

    /**
     * 根据用户账号查询角色
     *
     * @param userAccount 用户账号
     * @return 角色信息集合
     */
    public List<SysRole> listRolesByUserAccount(String userAccount) {
        return baseMapper.listRolesByUserAccount(userAccount);
    }
}
