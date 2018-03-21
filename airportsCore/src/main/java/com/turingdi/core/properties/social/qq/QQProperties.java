/**
 * 
 */
package com.turingdi.core.properties.social.qq;

import org.springframework.boot.autoconfigure.social.SocialProperties;

/**
 * 配置QQ登陆属性
 * 父类中提供appId、appSecret;
 * created by chuIllusions_tan 20180302
 */
public class QQProperties extends SocialProperties {
	
	private String providerId = "qq";

	public String getProviderId() {
		return providerId;
	}

	public void setProviderId(String providerId) {
		this.providerId = providerId;
	}
	
}
