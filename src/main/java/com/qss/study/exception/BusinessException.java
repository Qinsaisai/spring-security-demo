package com.qss.study.exception;

import org.springframework.http.HttpStatus;

public class BusinessException extends RuntimeException {

    public static final HttpStatus DEFAULT_HTTP_STATUS = HttpStatus.INTERNAL_SERVER_ERROR;

    private ErrorCode errorCode;
    private HttpStatus status;
    private Object[] args;

    public BusinessException() {
        super();
    }

    public BusinessException(String message) {
        super(message);
    }

    public BusinessException(Throwable throwable) {
        super(throwable);
    }

    public BusinessException(String message, Throwable throwable) {
        super(message, throwable);
    }

    public static BusinessException of(ErrorCode errorCode, Throwable cause) {
        return of(errorCode, DEFAULT_HTTP_STATUS, cause);
    }

    public static BusinessException of(ErrorCode errorCode, HttpStatus status, Throwable cause) {
        BusinessException ex = new BusinessException(cause);
        ex.setErrorCode(errorCode);
        ex.setStatus(status);
        return ex;
    }

    public static BusinessException of(ErrorCode errorCode, Throwable cause, Object... args) {
        return of(errorCode, DEFAULT_HTTP_STATUS, cause, args);
    }

    public static BusinessException of(ErrorCode errorCode, HttpStatus status, Throwable cause, Object... args) {
        BusinessException ex = new BusinessException(cause);
        ex.setErrorCode(errorCode);
        ex.setStatus(status);
        ex.setArgs(args);
        return ex;
    }

    public static BusinessException of(ErrorCode errorCode, Object... args) {
        return of(errorCode, DEFAULT_HTTP_STATUS, args);
    }

    public static BusinessException of(ErrorCode errorCode, HttpStatus status, Object... args) {
        BusinessException ex = new BusinessException();
        ex.setErrorCode(errorCode);
        ex.setStatus(status);
        ex.setArgs(args);
        return ex;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public void setStatus(HttpStatus status) {
        this.status = status;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }

    public Object[] getArgs() {
        return args;
    }

    public void setArgs(Object[] args) {
        this.args = args;
    }
}
