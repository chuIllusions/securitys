/**
 * 
 */
package com.turingdi.browser.config;

import com.turingdi.core.authentication.config.AbstractAuthenticationMethodSecurityConfig;
import com.turingdi.core.authentication.config.AuthenticationMethodSecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

/**
 * 浏览器环境下扩展点配置，配置在这里的bean，业务系统都可以通过声明同类型或同名的bean来覆盖安全
 * 模块默认的配置。
 * 
 * created by chuIllusions_tan on 20180308
 *
 */
@Configuration
public class BrowserSecurityBeanConfig {

	@Autowired
	private AuthenticationFailureHandler authenticationFailureHandler;

	@Autowired
	private AuthenticationSuccessHandler authenticationSuccessHandler;

	@Autowired
	private DataSource dataSource;

	/**
	 * 配置默认的认证方式，默认使用表单认证
	 * 若要自定义,则声明一个AuthenticationMethodSecurityConfig的实现类并被spring管理
	 * @return
	 */
	@Bean
	@ConditionalOnMissingBean(AuthenticationMethodSecurityConfig.class)
	public AuthenticationMethodSecurityConfig authenticationMethodSecurityConfig(){
		AbstractAuthenticationMethodSecurityConfig abstractAuthenticationMethodSecurityConfig =
				new AbstractAuthenticationMethodSecurityConfig(authenticationSuccessHandler,authenticationFailureHandler);
		return abstractAuthenticationMethodSecurityConfig;
	}



	/**
	 * 配置是否开启remmemberMe功能
	 * 只有配置中存在turing.security.browser.remember-me" 并且值为true才会生效
	 * @return
	 */
	@Bean
	@ConditionalOnProperty(prefix = "turing.security.browser", name = "remember-me", havingValue = "true")
	public PersistentTokenRepository persistentTokenRepository() {
		JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
		tokenRepository.setDataSource(dataSource);
		tokenRepository.setCreateTableOnStartup(true);//启动的时候建表
		return tokenRepository;
	}


}
