package com.qss.study.dto;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.util.List;

@Data
public class UserInfo {
    @ApiModelProperty(value = "主键id")
    private Integer userId;

    @ApiModelProperty(value = "用户名")
    private String userName;

    @ApiModelProperty(value = "用户账号")
    private String userAccount;

    @ApiModelProperty(value = "密码")
    private String password;

    @ApiModelProperty(value = "账号类型")
    private String accountType;

    @ApiModelProperty(value = "锁定标记")
    private String lockFlag;

    @ApiModelProperty(value = "手机号")
    private String phone;

    @ApiModelProperty(value = "邮箱")
    private String email;

    @ApiModelProperty(value = "逻辑删除标识（0-正常,1-删除）")
    private String delFlag;

    @ApiModelProperty(value = "角色编号")
    private List<String> roleCodeList;

}
