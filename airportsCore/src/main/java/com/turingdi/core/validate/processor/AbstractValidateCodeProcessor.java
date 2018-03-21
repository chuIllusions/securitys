/**
 * 
 */
package com.turingdi.core.validate.processor;

import com.turingdi.core.validate.code.common.ValidateCodeException;
import com.turingdi.core.validate.code.common.ValidateCode;
import com.turingdi.core.validate.code.common.ValidateCodeGenerator;
import com.turingdi.core.validate.code.common.ValidateCodeProcessor;
import com.turingdi.core.validate.code.common.ValidateCodeType;
import com.turingdi.core.validate.repository.ValidateCodeRepository;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.Map;

/**
 * 使用模板方法进行抽取
 * 生成可重用的验证码操作逻辑
 *
 * created by chuIllusions_tan 20180228
 */
public abstract class AbstractValidateCodeProcessor<C extends ValidateCode> implements ValidateCodeProcessor {

	/**
	 * spring中的依赖查找
	 * 所有验证码生成器
	 *
	 */
	@Autowired
	private Map<String, ValidateCodeGenerator> validateCodeGenerators;

	//验证码存储接口
	@Autowired
	private ValidateCodeRepository validateCodeRepository;

	/**
	 * 主干逻辑想通过，但处理不同
	 * 1.创建验证码
	 * 2.保存验证码
	 * 3.发送验证码
	 */
	@Override
	public void create(ServletWebRequest request) throws Exception {
		C validateCode = generate(request);
		save(request, validateCode);
		send(request, validateCode);
	}
	
	/**
	 * 生成校验码
	 * @param request
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private C generate(ServletWebRequest request) {
		String type = getProcessorType(request);
		ValidateCodeGenerator validateCodeGenerator = validateCodeGenerators.get(type + "ValidateCodeGenerator");
		return (C) validateCodeGenerator.generate(request);
	}

	/**
	 * 保存校验码
	 * @param request
	 * @param validateCode
	 */
	private void save(ServletWebRequest request, C validateCode) {
		ValidateCode code = new ValidateCode(validateCode.getCode(),validateCode.getExpireTime());
		//sessionStrategy.setAttribute(request, SESSION_KEY_PREFIX + getProcessorType(request).toUpperCase(), code);
		validateCodeRepository.save(request, code, getValidateCodeType(request));
	}

	/**
	 * 发送校验码，由子类实现
	 * @param request
	 * @param validateCode
	 * @throws Exception
	 */
	protected abstract void send(ServletWebRequest request, C validateCode) throws Exception;
	/**
	 * 根据请求的url获取校验码的类型
	 * @param request
	 * @return
	 */
	private String getProcessorType(ServletWebRequest request) {
		return StringUtils.substringAfter(request.getRequest().getRequestURI(), "/code/");
	}

	@SuppressWarnings("unchecked")
	@Override
	public void validate(ServletWebRequest request) {

		ValidateCodeType processorType = getValidateCodeType(request);

		C codeInSession = (C) validateCodeRepository.get(request, processorType);

		String codeInRequest;
		try {
			codeInRequest = ServletRequestUtils.getStringParameter(request.getRequest(),
					processorType.getParamNameOnValidate());
		} catch (ServletRequestBindingException e) {
			throw new ValidateCodeException("获取验证码的值失败");
		}

		if (StringUtils.isBlank(codeInRequest)) {
			throw new ValidateCodeException(processorType + "验证码的值不能为空");
		}

		if (codeInSession == null) {
			throw new ValidateCodeException(processorType + "验证码不存在");
		}

		if (codeInSession.isExpried()) {
			validateCodeRepository.remove(request, processorType);
			throw new ValidateCodeException(processorType + "验证码已过期");
		}

		if (!StringUtils.equals(codeInSession.getCode(), codeInRequest)) {
			throw new ValidateCodeException(processorType + "验证码不匹配");
		}

		validateCodeRepository.remove(request, processorType);
	}

	/**
	 * 构建验证码放入session时的key
	 *
	 * @param request
	 * @return
	 */
	private String getSessionKey(ServletWebRequest request) {
		return SESSION_KEY_PREFIX + getValidateCodeType(request).toString().toUpperCase();
	}

	/**
	 * 根据请求的url获取校验码的类型
	 *
	 * @param request
	 * @return
	 */
	private ValidateCodeType getValidateCodeType(ServletWebRequest request) {
		String type = StringUtils.substringBefore(getClass().getSimpleName(), "CodeProcessor");
		return ValidateCodeType.valueOf(type.toUpperCase());
	}
}
