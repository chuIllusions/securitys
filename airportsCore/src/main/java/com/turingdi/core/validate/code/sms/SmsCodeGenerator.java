/**
 * 
 */
package com.turingdi.core.validate.code.sms;

import com.turingdi.core.properties.SecurityProperties;
import com.turingdi.core.validate.code.common.ValidateCode;
import com.turingdi.core.validate.code.common.ValidateCodeGenerator;
import org.apache.commons.lang.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * 短信验证码生成器
 *
 * created by chuIllusions_tan 20180301
 */
public class SmsCodeGenerator implements ValidateCodeGenerator {

	@Autowired
	private SecurityProperties securityProperties;

	/**
	 * 短信验证码生成
	 * @param request 请求
	 * @return 验证码实现类
	 */
	@Override
	public ValidateCode generate(ServletWebRequest request) {
		String code = RandomStringUtils.randomNumeric(securityProperties.getCode().getSms().getLength());
		return new SmsCode(code, securityProperties.getCode().getSms().getExpireIn());
	}

	public SecurityProperties getSecurityProperties() {
		return securityProperties;
	}

	public void setSecurityProperties(SecurityProperties securityProperties) {
		this.securityProperties = securityProperties;
	}
}
