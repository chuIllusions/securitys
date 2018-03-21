/**
 * 
 */
package com.turingdi.core.validate.code.common;

import org.springframework.web.context.request.ServletWebRequest;

/**
 * 校验码处理器，封装不同校验码的处理逻辑
 *
 * created by chuIllusions_tan 20180301
 */
public interface ValidateCodeProcessor {
	
	/**
	 * 验证码放入session时的前缀
	 */
	String SESSION_KEY_PREFIX = "SESSION_KEY_FOR_CODE_";
	
	/**
	 * 创建校验码
	 * @param request 工具类，request or response 都可以放入此包装类
	 */
	void create(ServletWebRequest request) throws Exception;

	/**
	 * 校验验证码
	 *
	 * @param servletWebRequest 工具类，request or response 都可以放入此包装类
	 */
	void validate(ServletWebRequest servletWebRequest);
}
