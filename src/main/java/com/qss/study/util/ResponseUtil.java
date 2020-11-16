package com.qss.study.util;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.http.ContentType;
import com.alibaba.fastjson.JSON;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class ResponseUtil {

    public static void ResponseResult(HttpServletResponse response, String code, String message, int status, Object data) throws IOException {
        Map<String,Object> result=new HashMap<>();
        result.put("code",code);
        result.put("message",message);
        result.put("data",data);
        String loginUser = JSON.toJSONString(result);
        response.setStatus(status);
        response.setCharacterEncoding(CharsetUtil.UTF_8);
        response.setContentType(ContentType.JSON.toString());
        response.getWriter().write(loginUser);
    }
}
