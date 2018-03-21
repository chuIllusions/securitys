/**
 * 
 */
package com.turingdi.server.jwt;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.Map;

/**
 * 对jwt进行扩展增强
 * 系统的默认实现
 *
 * created by chuIllusions_tan on 20180309
 */
public class AbstractJwtTokenEnhancer implements TokenEnhancer {

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		//需要往token加入的信息
		Map<String, Object> info = new HashMap<>();
		info.put("company", "turing");
		
		((DefaultOAuth2AccessToken)accessToken).setAdditionalInformation(info);
		
		return accessToken;
	}

}
