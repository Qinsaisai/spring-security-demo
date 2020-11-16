package com.qss.study.util;

import com.qss.study.dto.LoginUserInfo;
import lombok.Data;

/**
 * JwtPayLoad部分
 *
 */
@Data
public class JwtPayLoad {
    /**
     * 当前用户信息
     *
     * 此处不应该将用户敏感信息等全部放到JwtPayLoad部分生成token中，因为token并非是绝对安全的
     */
    private String userAccount;

    public JwtPayLoad(){

    }
    public JwtPayLoad(String userAccount){
        this.userAccount=userAccount;
    }
}
