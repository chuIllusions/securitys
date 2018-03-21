/**
 * 
 */
package com.turingdi.browser.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.turingdi.browser.authentication.login.AbstractBrowserAuthenticationFailureHandler;
import com.turingdi.browser.authentication.login.AbstractBrowserAuthenticationSuccessHandler;
import com.turingdi.browser.authentication.logout.AbstractLogoutSuccessHandler;
import com.turingdi.core.properties.SecurityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * 认证结果处理器相关的扩展点配置。配置在这里的bean，业务系统都可以通过声明同类型或同名的bean来覆盖安全
 * 模块默认的配置。
 *
 * created by chuIllusions_tan 20180308
 */
@Configuration
public class AuthenticationHandlerBeanConfig {

	@Autowired
	private ObjectMapper objectMapper;
	
	@Autowired
	private SecurityProperties securityProperties;
	
	/**
	 * 默认的登录失败处理器
	 * @return AuthenticationFailureHandler
	 */
	@Bean
	@ConditionalOnMissingBean(name = "turingAuthenticationFailureHandler")
	public AuthenticationFailureHandler abstractAuthenticationFailureHandler() {
		AbstractBrowserAuthenticationFailureHandler abstractBrowserAuthenticationFailureHandler = new AbstractBrowserAuthenticationFailureHandler();
		abstractBrowserAuthenticationFailureHandler.setSecurityProperties(securityProperties);
		abstractBrowserAuthenticationFailureHandler.setObjectMapper(objectMapper);
		return abstractBrowserAuthenticationFailureHandler;
	}

	/**
	 * 默认的登录成功处理器
	 * @return AuthenticationSuccessHandler
	 */
	@Bean
	@ConditionalOnMissingBean(name = "turingAuthenticationSuccessHandler")
	public AuthenticationSuccessHandler abstractAuthenticationSuccessHandler() {
		AbstractBrowserAuthenticationSuccessHandler abstractBrowserAuthenticationSuccessHandler = new AbstractBrowserAuthenticationSuccessHandler();
		abstractBrowserAuthenticationSuccessHandler.setSecurityProperties(securityProperties);
		abstractBrowserAuthenticationSuccessHandler.setObjectMapper(objectMapper);
		return abstractBrowserAuthenticationSuccessHandler;
	}

	/**
	 * 退出登录时跳转的策略
	 */
	@Bean
	@ConditionalOnMissingBean(LogoutSuccessHandler.class)
	public LogoutSuccessHandler logoutSuccessHandler(){
		AbstractLogoutSuccessHandler abstractLogoutSuccessHandler= new AbstractLogoutSuccessHandler(securityProperties.getBrowser().getSignOutUrl());
		abstractLogoutSuccessHandler.setObjectMapper(objectMapper);
		return abstractLogoutSuccessHandler;
	}


}
