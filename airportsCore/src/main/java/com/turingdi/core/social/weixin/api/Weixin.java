/**
 * 
 */
package com.turingdi.core.social.weixin.api;

/**
 * 微信API调用接口
 * 
 * created by chuIllusions_tan 20180302
 *
 */
public interface Weixin {

	WeixinUserInfo getUserInfo(String openId);
	
}
