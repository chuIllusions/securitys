/**
 * 
 */
package com.turingdi.core.validate.config;

import com.turingdi.core.properties.SecurityProperties;
import com.turingdi.core.validate.code.common.ValidateCodeGenerator;
import com.turingdi.core.validate.code.image.ImageCodeGenerator;
import com.turingdi.core.validate.code.sms.SmsCodeGenerator;
import com.turingdi.core.validate.code.sms.sender.SmsCodeSender;
import com.turingdi.core.validate.code.sms.sender.impl.DefaultSmsCodeSender;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
/**
 * 验证码相关的扩展点配置。配置在这里的bean，业务系统都可以通过声明同类型或同名的bean来覆盖安全
 * 模块默认的配置。
 *
 * created by chuIllusions_tan 20180308
 */
@Configuration
public class ValidateCodeBeanConfig {
	
	@Autowired
	private SecurityProperties securityProperties;
	
	/**
	 * 图片验证码图片生成器
	 * @return ValidateCodeGenerator图片验证码生成器
	 */
	@Bean
	@ConditionalOnMissingBean(name = "imageValidateCodeGenerator")
	public ValidateCodeGenerator imageValidateCodeGenerator() {
		ImageCodeGenerator codeGenerator = new ImageCodeGenerator();
		codeGenerator.setSecurityProperties(securityProperties);
		return codeGenerator;
	}

	/**
	 * 短信验证码生成器
	 *  @return ValidateCodeGenerator短信验证码生成器
	 */
	@Bean
	@ConditionalOnMissingBean(name = "smsValidateCodeGenerator")
	public ValidateCodeGenerator smsValidateCodeGenerator() {
		SmsCodeGenerator codeGenerator = new SmsCodeGenerator();
		codeGenerator.setSecurityProperties(securityProperties);
		return codeGenerator;
	}
	
	/**
	 * 短信验证码发送器
	 * @return SmsCodeSender 默认实现类
	 */
	@Bean
	@ConditionalOnMissingBean(SmsCodeSender.class)
	public SmsCodeSender smsCodeSender() {
		return new DefaultSmsCodeSender();
	}

}
