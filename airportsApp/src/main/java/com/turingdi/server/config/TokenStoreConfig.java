/**
 * 
 */
package com.turingdi.server.config;

import com.turingdi.server.jwt.AbstractJwtTokenEnhancer;
import com.turingdi.core.properties.SecurityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

/**
 * 配置token的存储类型
 *
 * created by chuIllusions_tan on 20180309
 */
@Configuration
public class TokenStoreConfig {

	//redis连接工厂
	@Autowired
	private RedisConnectionFactory redisConnectionFactory;

	//配置token存储方式，如果不是指定值则下面配置不生效
	//只有配置中存在vic.security.oauth2.tokenStore 并且值为redis才会生效
	@Bean
	@ConditionalOnProperty(prefix = "turing.security.oauth2", name = "tokenStore", havingValue = "redis")
	public TokenStore redisTokenStore() {
		return new RedisTokenStore(redisConnectionFactory);
	}

	//需要配置一系列的bean
	//配置token存储方式，如果不是指定值则下面配置不生效
	//matchIfMissing = true : 当配置文件中不存在vic.security.oauth2tokenStore不存在，以下配置也生效
	@Configuration
	@ConditionalOnProperty(prefix = "vic.security.oauth2", name = "tokenStore", havingValue = "jwt", matchIfMissing = true)
	public static class JwtConfig {

		@Autowired
		private SecurityProperties securityProperties;

		//只负责存储，不负责生成
		@Bean
		public TokenStore jwtTokenStore() {
			return new JwtTokenStore(jwtAccessTokenConverter());
		}

		//token生成的一些处理
		@Bean
		public JwtAccessTokenConverter jwtAccessTokenConverter(){
			JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
			//设置签名密钥
			converter.setSigningKey(securityProperties.getOauth2().getJwtSigningKey());
			return converter;
		}

		/**
		 * 可配置扩展
		 * 默认使用系统实现类
		 * @return
		 */
		@Bean
		@ConditionalOnBean(TokenEnhancer.class)
		public TokenEnhancer jwtTokenEnhancer(){
			return new AbstractJwtTokenEnhancer();
		}

	}

}
