/**
 * 
 */
package com.turingdi.browser.config;

import com.turingdi.core.authentication.config.AuthenticationMethodSecurityConfig;
import com.turingdi.core.authentication.mobile.config.SmsCodeAuthenticationSecurityConfig;
import com.turingdi.core.authorize.AuthorizeConfigManager;
import com.turingdi.core.properties.SecurityProperties;
import com.turingdi.core.validate.config.ValidateCodeSecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.social.security.SpringSocialConfigurer;

/**
 * 浏览器项目的安全配置
 *
 * created by chuIllusions_tan 20180227
 */
@Configuration
public class BrowserSecurityConfig  extends WebSecurityConfigurerAdapter {

	@Autowired
	private SecurityProperties securityProperties;

	@Autowired
	private AuthenticationMethodSecurityConfig authenticationMethodSecurityConfig;

	@Autowired
	private AuthorizeConfigManager authorizeConfigManager;


	@Autowired
	private InvalidSessionStrategy invalidSessionStrategy;

	@Autowired
	private SessionInformationExpiredStrategy sessionInformationExpiredStrategy;

	@Autowired
	private LogoutSuccessHandler logoutSuccessHandler;

	//校验码过滤器配置
	@Autowired
	private ValidateCodeSecurityConfig validateCodeSecurityConfig;

	//短信登录过滤器配置
	@Autowired
	private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;

	//配置RemmberMe所需要的数据操作仓库
	@Autowired(required = false)
	private PersistentTokenRepository persistentTokenRepository;

	@Autowired
	private UserDetailsService userDetailsService;

	//spring social配置注入
	@Autowired
	private SpringSocialConfigurer socialSecurityConfig;


	/**
	 * 配置浏览器特有的安全配置，并且读取全局配置，加入spring security安全配置中
	 * @param http
	 * @throws Exception
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		//应用配置好的认证形式，否则将使用spring security默认的Http Basic认证
		if (authenticationMethodSecurityConfig != null)
			authenticationMethodSecurityConfig.applyMethodAuthenticationConfig(http);

		//应用自定义功能:验证码过滤器、手机验证码登陆过滤器、社交登陆配置
		http.apply(validateCodeSecurityConfig)
				.and()
				.apply(smsCodeAuthenticationSecurityConfig)
				.and()
				.apply(socialSecurityConfig);


		//开启session管理功能
		http.sessionManagement()
				.invalidSessionStrategy(invalidSessionStrategy)//session过期处理器
				.maximumSessions(securityProperties.getBrowser().getSession().getMaximumSessions())//用户最大session数
				.maxSessionsPreventsLogin(securityProperties.getBrowser().getSession().isMaxSessionsPreventsLogin())//是否阻止并发登录
				.expiredSessionStrategy(sessionInformationExpiredStrategy);//session并发处理器

		//是否开启remmemberMe功能
		if (persistentTokenRepository != null){
			http.rememberMe()
					.tokenRepository(persistentTokenRepository)//配置数据每个用户对应的token
					.tokenValiditySeconds(securityProperties.getBrowser().getRememberMeSeconds())
					.userDetailsService(userDetailsService);//拿到用户名后从该user找到用户
		}

		//退出登录管理
		http.logout()
				.logoutUrl("/signOut")
				.logoutSuccessHandler(logoutSuccessHandler)//配置了handler会使这条配置失效.logoutSuccessUrl("")
				.deleteCookies("JSESSIONID");

		//关闭跨站伪造服务
		http.csrf().disable();

		//调用所有模块的资源权限配置,添加如spring security安全配置中
		authorizeConfigManager.config(http.authorizeRequests());
	}



}
