/**
 * 
 */
package com.turingdi.browser.authorize;

import com.turingdi.core.authorize.AuthorizeConfigProvider;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.stereotype.Component;

/**
 * 浏览器环境默认的授权配置，对常见的静态资源，如js,css，图片等不验证身份
 * 
 * created by chuIllusions_tan on 20180308
 *
 */
@Component
@Order(Integer.MIN_VALUE)
public class BrowserAuthorizeConfigProvider implements AuthorizeConfigProvider {

	@Override
	public boolean config(ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry config) {
		config.antMatchers(HttpMethod.GET, 
			"/**/*.js",
			"/**/*.css",
			"/**/*.jpg",
			"/**/*.png",
			"/**/*.gif","/thymeleaf/home").permitAll();
		config.antMatchers("/thymeleaf/admins").hasAnyRole("ADMIN")
				.antMatchers("/thymeleaf/users").hasAnyRole("USER");
		return false;
	}

}
