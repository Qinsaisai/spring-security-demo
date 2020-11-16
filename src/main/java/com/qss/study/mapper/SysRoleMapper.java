package com.qss.study.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.qss.study.entity.SysRole;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface SysRoleMapper extends BaseMapper<SysRole> {

    /**
     * 通过用户账号，查询角色信息
     *
     * @param userAccount 用户账号
     * @return 角色信息集合
     */
    List<SysRole> listRolesByUserAccount(String userAccount);
}
