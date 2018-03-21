/**
 * 
 */
package com.turingdi.server.config;

import com.turingdi.core.authorize.AuthorizeConfigProvider;
import com.turingdi.core.properties.SecurityConstants;
import com.turingdi.core.properties.SecurityProperties;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.stereotype.Component;

/**
 * App模块的安全配置
 * 配置资源的权限
 *
 * created by chuIllusions_tan on 20180309
 */
@Component
@Order(Integer.MIN_VALUE)
public class AppAuthorizeConfigProvider implements AuthorizeConfigProvider {

	@Autowired
	private SecurityProperties securityProperties;
	
	@Override
	public boolean config(ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry config) {
		config.antMatchers(
				"/user/regist",SecurityConstants.DEFAULT_APP_SOCIAL_SIGN_UP_URL).permitAll();

		return false;
	}

}
