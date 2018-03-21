/**
 * 
 */
package com.turingdi.core.validate.code.common;

import org.springframework.web.context.request.ServletWebRequest;

/**
 * 验证码生成器接口
 *
 * created by chuIllusions_tan 20180301
 */
public interface ValidateCodeGenerator {

	ValidateCode generate(ServletWebRequest request);
	
}
