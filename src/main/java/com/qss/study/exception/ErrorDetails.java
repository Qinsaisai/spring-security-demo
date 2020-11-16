package com.qss.study.exception;

import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.web.context.request.WebRequest;

import java.text.MessageFormat;
import java.time.ZonedDateTime;
import java.util.Objects;

@Data
public class ErrorDetails {
    private Integer status;
    private String error;
    private String code;
    private String message;
    private String path;
    private ZonedDateTime timestamp = ZonedDateTime.now();

    public static ErrorDetails from(ErrorCode errorCode, WebRequest request, Throwable cause) {
        BusinessException ex = BusinessException.of(errorCode, cause);
        return ErrorDetails.from(ex, request);
    }

    public static ErrorDetails from(ErrorCode errorCode, WebRequest request, Throwable cause, Object... args) {
        BusinessException ex = BusinessException.of(errorCode, cause, args);
        return ErrorDetails.from(ex, request);
    }

    public static ErrorDetails from(ErrorCode errorCode, HttpStatus status, WebRequest request, Throwable cause) {
        BusinessException ex = BusinessException.of(errorCode, status, cause);
        return ErrorDetails.from(ex, request);
    }

    public static ErrorDetails from(ErrorCode errorCode, HttpStatus status, WebRequest request, Throwable cause, Object... args) {
        BusinessException ex = BusinessException.of(errorCode, status, cause, args);
        return ErrorDetails.from(ex, request);
    }

    public static ErrorDetails from(BusinessException ex, WebRequest request) {
        ErrorDetails details = new ErrorDetails();
        details.setCode(ex.getErrorCode().getCode());
        Object[] args = ex.getArgs();
        if (Objects.isNull(args) || args.length <= 0) {
            details.setMessage(ex.getErrorCode().getMessage());
        } else {
            String message = MessageFormat.format(ex.getErrorCode().getMessage(), args);
            details.setMessage(message);
        }
        details.setStatus(ex.getStatus().value());
        details.setError(ex.getStatus().getReasonPhrase());
        details.setPath(request.getDescription(false));
        return details;
    }
}
