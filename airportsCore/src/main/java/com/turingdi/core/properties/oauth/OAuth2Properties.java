/**
 * 
 */
package com.turingdi.core.properties.oauth;

import com.turingdi.core.properties.SecurityConstants;

/**
 * OAUTH 相关属性配置
 *
 * created by chuIllusions_tan on 20180309
 *
 */
public class OAuth2Properties {
	
	/**
	 * 使用jwt时为token签名的秘钥
	 */
	private String jwtSigningKey = SecurityConstants.DEFAULT_JWT_KEY;

	/**
	 * 客户端信息配置
	 */
	private OAuth2ClientProperties[] clients = {};

	public OAuth2ClientProperties[] getClients() {
		return clients;
	}

	public void setClients(OAuth2ClientProperties[] clients) {
		this.clients = clients;
	}

	public String getJwtSigningKey() {
		return jwtSigningKey;
	}

	public void setJwtSigningKey(String jwtSigningKey) {
		this.jwtSigningKey = jwtSigningKey;
	}
	
}
