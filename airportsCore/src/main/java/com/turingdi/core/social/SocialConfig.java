/**
 * 
 */
package com.turingdi.core.social;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.turingdi.core.properties.SecurityConstants;
import com.turingdi.core.properties.SecurityProperties;
import com.turingdi.core.social.support.AbstractConnectionViewProcessor;
import com.turingdi.core.social.support.AbstractSpringSocialConfigurer;
import com.turingdi.core.social.support.DefaultConnectionViewProcessor;
import com.turingdi.core.social.support.SocialAuthenticationFilterPostProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.social.config.annotation.EnableSocial;
import org.springframework.social.config.annotation.SocialConfigurerAdapter;
import org.springframework.social.connect.ConnectionFactoryLocator;
import org.springframework.social.connect.ConnectionSignUp;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.social.connect.jdbc.JdbcUsersConnectionRepository;
import org.springframework.social.connect.web.ProviderSignInUtils;
import org.springframework.social.security.SpringSocialConfigurer;

import javax.sql.DataSource;

/**
 * 配置社交登陆配置
 * created by chuIllusions_tan 20180302
 */
@Configuration
@EnableSocial//开启社交项目的支持
public class SocialConfig extends SocialConfigurerAdapter {
	private Logger logger = LoggerFactory.getLogger(this.getClass());
	
	@Autowired
	private DataSource dataSource;

	@Autowired
	private SecurityProperties securityProperties;

	@Autowired(required = false)
	private ConnectionSignUp connectionSignUp;

	@Autowired(required = false)
	private SocialAuthenticationFilterPostProcessor socialAuthenticationFilterPostProcessor;

	@Override
	public UsersConnectionRepository getUsersConnectionRepository(ConnectionFactoryLocator connectionFactoryLocator) {
		JdbcUsersConnectionRepository repository = new JdbcUsersConnectionRepository(dataSource, connectionFactoryLocator, Encryptors.noOpText());
		repository.setTablePrefix("vic_");//加入表前缀
		if(connectionSignUp != null) {
			repository.setConnectionSignUp(connectionSignUp);
		}
		return repository;
	}

	/**
	 * 全局配置SocailConfig
	 * @return
	 */
	@Bean(name = SecurityConstants.DEFAULT_SPRING_SOCIAL_CONFIGURER_BEAN_NAME)
	public SpringSocialConfigurer socialSecurityConfig() {
		String filterProcessesUrl = securityProperties.getSocial().getFilterProcessesUrl();
		AbstractSpringSocialConfigurer configurer = new AbstractSpringSocialConfigurer(filterProcessesUrl);
		//设置注册地址
		configurer.signupUrl(securityProperties.getBrowser().getSignUpUrl());
		//设置后置处理器，对过滤器进行增强改造
		configurer.setSocialAuthenticationFilterPostProcessor(socialAuthenticationFilterPostProcessor);
		return configurer;
	}

	/**
	 * spring social 提供的工具类，可以获取获取到的第三方用户信息
	 * @param connectionFactoryLocator spring boot 已经有此类的实现
	 * @return ProviderSignInUtils
	 */
	@Bean
	public ProviderSignInUtils providerSignInUtils(ConnectionFactoryLocator connectionFactoryLocator) {
		UsersConnectionRepository usersConnectionRepository = getUsersConnectionRepository(connectionFactoryLocator);
		return new ProviderSignInUtils(connectionFactoryLocator,usersConnectionRepository);
	}

	/**
	 * 配置默认的社交绑定状态信息输出器
	 * 可扩展
	 */
	@Bean
	@ConditionalOnMissingBean(AbstractConnectionViewProcessor.class)
	public AbstractConnectionViewProcessor connectionViewProcessor(ObjectMapper objectMapper){
		DefaultConnectionViewProcessor processor = new DefaultConnectionViewProcessor(objectMapper);
		return processor;
	}
}
