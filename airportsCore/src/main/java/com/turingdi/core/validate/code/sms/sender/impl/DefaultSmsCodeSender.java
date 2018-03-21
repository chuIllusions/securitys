/**
 * 
 */
package com.turingdi.core.validate.code.sms.sender.impl;

import com.turingdi.core.validate.code.sms.sender.SmsCodeSender;

/**
 * 短信验证码发送者实现发送接口默认实现类
 * 自定义可以覆盖默认实现类
 * created by chuIllusions_tan 20180301
 */
public class DefaultSmsCodeSender implements SmsCodeSender {

	@Override
	public void send(String mobile, String code) {
		//模拟实现
		System.out.println("向手机"+mobile+"发送短信验证码"+code);
	}

}
