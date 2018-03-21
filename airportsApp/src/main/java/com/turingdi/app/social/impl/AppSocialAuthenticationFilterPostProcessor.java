/**
 * 
 */
package com.turingdi.app.social.impl;

import com.turingdi.core.social.support.SocialAuthenticationFilterPostProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.social.security.SocialAuthenticationFilter;
import org.springframework.stereotype.Component;

/**
 * 定义后处理器接口实现类，
 * 修改SocialAuthenticationFilter里的成功处理器
 * 处理App模式下授权后（身份验证成功）返回的信息
 *
 * created by chuIllusion_tan 20180308
 */
@Component
public class AppSocialAuthenticationFilterPostProcessor implements SocialAuthenticationFilterPostProcessor {
	
	@Autowired
	private AuthenticationSuccessHandler authenticationSuccessHandler;

	@Override
	public void process(SocialAuthenticationFilter socialAuthenticationFilter) {
		socialAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
	}

}
