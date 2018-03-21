/**
 * 
 */
package com.turingdi.core.validate.code.common;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 校验码器寻找
 * 目的:使用srping的依赖注入寻找所有的验证码验证码处理器
 *
 * created by chuIllusions_tan 20180308
 */
@Component
public class ValidateCodeProcessorHolder {

	@Autowired
	private Map<String, ValidateCodeProcessor> validateCodeProcessors;

	public ValidateCodeProcessor findValidateCodeProcessor(ValidateCodeType type) {
		return findValidateCodeProcessor(type.toString().toLowerCase());
	}

	public ValidateCodeProcessor findValidateCodeProcessor(String type) {
		String name = type.toLowerCase() + ValidateCodeProcessor.class.getSimpleName();
		ValidateCodeProcessor processor = validateCodeProcessors.get(name);
		if (processor == null) {
			throw new ValidateCodeException("验证码处理器" + name + "不存在");
		}
		return processor;
	}

}
