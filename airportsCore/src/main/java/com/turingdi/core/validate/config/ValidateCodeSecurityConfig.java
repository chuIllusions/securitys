/**
 * 
 */
package com.turingdi.core.validate.config;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.stereotype.Component;

/**
 * 校验码相关安全配置
 *
 * created by chuIllusions_tan 20180308
 */
@Component("validateCodeSecurityConfig")
public class ValidateCodeSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	@Autowired
	private Filter validateCodeFilter;

	/**
	 * 将自定义的验证码校验过滤器加入spring sucurity的过滤器链中
	 * 为保证能在自定义的短信验证码登录AuthenticationFilter(自定义的像UsernamePasswordAuthentication类实现的功能)能比其他Authentication过滤器先在执行
	 * 因此将自定义的过滤器加在spring security 过滤器链中的AbstractPreAuthenticatedProcessingFilter
	 *
	 * @param http HttpSecurity
	 * @throws Exception
	 */
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(validateCodeFilter, AbstractPreAuthenticatedProcessingFilter.class);
	}
	
}
