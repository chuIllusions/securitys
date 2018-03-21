/**
 * 
 */
package com.turingdi.core.validate.code.common;

import org.springframework.security.core.AuthenticationException;

/**
 * 验证码异常类
 *
 * created by chuIllusions_tan 20180228
 */
public class ValidateCodeException extends AuthenticationException {

	private static final long serialVersionUID = -7285211528095468156L;

	public ValidateCodeException(String msg) {
		super(msg);
	}

}
