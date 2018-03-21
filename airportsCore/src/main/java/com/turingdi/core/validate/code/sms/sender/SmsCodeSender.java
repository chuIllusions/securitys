/**
 * 
 */
package com.turingdi.core.validate.code.sms.sender;

/**
 * 短信验证码发送者实现发送接口
 * created by chuIllusions_tan 20180301
 */
public interface SmsCodeSender {

	/**
	 * 短信验证码发送逻辑
	 * 需要开发者继承此接口，并实现业务处理逻辑
	 * @param mobile 手机号
	 * @param code 验证码
	 */
	void send(String mobile, String code);

}
