/**
 * 
 */
package com.turingdi.core.validate.code.sms;

import com.turingdi.core.properties.SecurityConstants;
import com.turingdi.core.validate.code.common.ValidateCode;
import com.turingdi.core.validate.code.sms.sender.SmsCodeSender;
import com.turingdi.core.validate.processor.AbstractValidateCodeProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;
/**
 * 短信验证码处理器
 * created by chuIllusions_tan 20180301
 */
@Component("smsValidateCodeProcessor")
public class SmsCodeProcessor extends AbstractValidateCodeProcessor<ValidateCode> {

	/**
	 * 短信验证码发送器
	 * 需要进行bean配置,默认使用核心包中的DefaultSmsCodeSender
	 */
	@Autowired
	private SmsCodeSender smsCodeSender;

	/**
	 * 发送处理逻辑不一样，需要重新实现
	 */
	@Override
	protected void send(ServletWebRequest request, ValidateCode validateCode) throws Exception {
		String mobile = ServletRequestUtils.getRequiredStringParameter(request.getRequest(), SecurityConstants.DEFAULT_PARAMETER_NAME_MOBILE);
		smsCodeSender.send(mobile, validateCode.getCode());
	}

}
