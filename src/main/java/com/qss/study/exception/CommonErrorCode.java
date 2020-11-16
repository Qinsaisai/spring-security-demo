package com.qss.study.exception;

public enum CommonErrorCode implements ErrorCode {
    /**
     * 登录失败
     */
    LOGIN_FAIL("LoginException","LoginException, for reason: {0}"),

    /**
     * 错误请求
     */
    INVALID_REQUEST("InvalidRequest", "Invalid request, for reason: {0}"),
    /**
     * 参数验证错误
     */
    INVALID_ARGUMENT("InvalidArgument", "Validation failed for argument [{0}], hints: {1}"),
    /**
     * 未找到资源
     */
    NOT_FOUND("NotFound", "Resource {0} not found."),
    /**
     * 未知错误
     */
    UNKNOWN_ERROR("UnknownError", "Unknown server internal error."),
    /**
     * 权限验证错误
     */
    AUTH_EXCEPTION("AuthException", "AuthException, for reason: {0}"),
    /**
     * token错误
     */
    TOKEN_EXCEPTION("TokenException", "TokenException,for reason:{0}"),

    /**
     * 禁止访问
     */
    FORBIDDEN("Forbidden", "Forbidden,for reason:{0}");

    CommonErrorCode(String code, String message) {
        this.code = code;
        this.message = message;
    }

    private final String code;
    private final String message;


    @Override
    public String getCode() {
        return code;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
