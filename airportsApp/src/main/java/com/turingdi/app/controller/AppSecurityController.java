/**
 * 
 */
package com.turingdi.app.controller;

import com.turingdi.app.social.utils.AppSingUpUtils;
import com.turingdi.core.properties.SecurityConstants;
import com.turingdi.core.social.support.SocialUserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.social.connect.Connection;
import org.springframework.social.connect.web.ProviderSignInUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@RestController
public class AppSecurityController {
	
	@Autowired
	private ProviderSignInUtils providerSignInUtils;
	
	@Autowired
	private AppSingUpUtils appSingUpUtils;
	
	@GetMapping(SecurityConstants.DEFAULT_APP_SOCIAL_SIGN_UP_URL)
	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	public SocialUserInfo getSocialUserInfo(HttpServletRequest request) {
		SocialUserInfo userInfo = new SocialUserInfo();
		//获得社交信息，spring social还是会将社交信息存储在session中，只是我们不能获得
		//可以通过ProviderSignInUtils工具获取存在session中的社交用户信息
		Connection<?> connection = providerSignInUtils.getConnectionFromSession(new ServletWebRequest(request));
		userInfo.setProviderId(connection.getKey().getProviderId());
		userInfo.setProviderUserId(connection.getKey().getProviderUserId());
		userInfo.setNickname(connection.getDisplayName());
		userInfo.setHeadimg(connection.getImageUrl());
		
		appSingUpUtils.saveConnectionData(new ServletWebRequest(request), connection.createData());
		
		return userInfo;
	}

}
