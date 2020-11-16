package com.qss.study.controller;

import com.qss.study.dto.LoginUserInfo;
import com.qss.study.service.SysUserService;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@Slf4j
@RestController
@RequestMapping("/user")
public class SysUserController {
    @Resource
    private SysUserService sysUserService;

    /**
     * 获取当前登录用户信息
     *
     * @return 当前登录用户信息
     */
    @ApiOperation("获取当前登录用户信息")
    @GetMapping("/getLoginUser")
    public LoginUserInfo getLoginUser() {
        return sysUserService.getLoginUser();
    }
}
