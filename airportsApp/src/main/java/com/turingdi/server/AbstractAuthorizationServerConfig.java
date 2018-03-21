/**
 * 
 */
package com.turingdi.server;

import com.turingdi.core.properties.SecurityProperties;
import com.turingdi.core.properties.oauth.OAuth2ClientProperties;
import org.apache.commons.lang.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.ArrayList;
import java.util.List;

/**
 * 实现认证服务器
 * 认证服务器和资源服务器可以时同一台机子
 * 所以在我们的项目中，认证服务器和资源服务器同在一个项目中
 *
 * 认证服务器就可以理解为第三方平台微信平台，需要获取该平台用户信息，需要授权
 *
 * created by chuIllusions_tan 20180304
 */
@Configuration
@EnableAuthorizationServer
public class AbstractAuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private SecurityProperties securityProperties;

    @Autowired(required = false)
    private JwtAccessTokenConverter jwtAccessTokenConverter;

    @Autowired(required = false)
    private TokenEnhancer jwtTokenEnhancer;

    /**
     * 配置服务器链接信息
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        //默认存储在内存
        endpoints.tokenStore(tokenStore)
                .authenticationManager(authenticationManager)//指定
                .userDetailsService(userDetailsService);//指定
        //配置token
        if (jwtAccessTokenConverter != null && jwtTokenEnhancer != null){
            //增加链条
            TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
            List<TokenEnhancer> enhancers = new ArrayList<>();
            enhancers.add(jwtTokenEnhancer);
            enhancers.add(jwtAccessTokenConverter);
            enhancerChain.setTokenEnhancers(enhancers);
            endpoints.tokenEnhancer(enhancerChain)
                    .accessTokenConverter(jwtAccessTokenConverter);
        }
    }

    /**
     * 配置客户端的链接信息
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        InMemoryClientDetailsServiceBuilder builder = clients.inMemory();
        if (ArrayUtils.isNotEmpty(securityProperties.getOauth2().getClients())) {
            for (OAuth2ClientProperties client : securityProperties.getOauth2().getClients()) {
                //配置第三方应用信息
                builder.withClient(client.getClientId())
                        .secret(client.getClientSecret())
                        //支持的哪一些授权模式
                        .authorizedGrantTypes("refresh_token", "authorization_code", "password")
                        //token的存储时间
                        .accessTokenValiditySeconds(client.getAccessTokenValidateSeconds())
                        //令牌的刷新时间
                        .refreshTokenValiditySeconds(2592000)
                        //支持授权范围
                        .scopes("all");
            }
        }
    }

    /**
     * tokenKey的访问权限表达式配置
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()");
    }
}
