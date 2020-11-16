package com.qss.study.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.qss.study.entity.SysUser;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface SysUserMapper extends BaseMapper<SysUser> {
    /**
     * 根据用户账号查询
     *
     * @param userAccount 用户账号
     * @return 用户实体
     */
    SysUser selectByUserAccount(String userAccount);
}
