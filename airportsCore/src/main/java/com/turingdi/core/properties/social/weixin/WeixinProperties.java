/**
 * 
 */
package com.turingdi.core.properties.social.weixin;

import org.springframework.boot.autoconfigure.social.SocialProperties;

/**
 * 微信属性
 *
 * created by chuIllusions_tan on 20280308
 */
public class WeixinProperties extends SocialProperties {
	
	/**
	 * 第三方id，用来决定发起第三方登录的url，默认是 weixin。
	 */
	private String providerId = "weixin";

	/**
	 * @return the providerId
	 */
	public String getProviderId() {
		return providerId;
	}

	/**
	 * @param providerId the providerId to set
	 */
	public void setProviderId(String providerId) {
		this.providerId = providerId;
	}
	

}
