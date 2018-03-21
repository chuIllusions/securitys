package com.turingdi.core.validate.code.sms;

import com.turingdi.core.validate.code.common.ValidateCode;

import java.time.LocalDateTime;

/**
 * 短信验证码
 * created by chuIllusions_tan 20170308
 */
public class SmsCode extends ValidateCode{

    public SmsCode(String code, int expireIn) {
        super(code, expireIn);
    }

    public SmsCode(String code, LocalDateTime expireTime) {
        super(code, expireTime);
    }
}
