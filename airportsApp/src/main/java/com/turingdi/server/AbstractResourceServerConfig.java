/**
 * 
 */
package com.turingdi.server;

import com.turingdi.app.social.openid.config.OpenIdAuthenticationSecurityConfig;
import com.turingdi.core.authentication.config.AuthenticationMethodSecurityConfig;
import com.turingdi.core.authentication.mobile.config.SmsCodeAuthenticationSecurityConfig;
import com.turingdi.core.authorize.AuthorizeConfigManager;
import com.turingdi.core.validate.config.ValidateCodeSecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.social.security.SpringSocialConfigurer;

/**
 * 开启资源服务器，支持access_token
 *
 * created by chuIllusions_tan 20180304
 */
@Configuration
@EnableResourceServer
public class AbstractResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private AuthorizeConfigManager authorizeConfigManager;

    @Autowired
    private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;

    @Autowired
    private ValidateCodeSecurityConfig validateCodeSecurityConfig;

    @Autowired
    private SpringSocialConfigurer socialSecurityConfig;

    @Autowired
    private AuthenticationMethodSecurityConfig authenticationMethodSecurityConfig;

    @Autowired
    private OpenIdAuthenticationSecurityConfig openIdAuthenticationSecurityConfig;

    @Override
    public void configure(HttpSecurity http) throws Exception {

        //应用配置好的认证形式，否则将使用spring security默认的Http Basic认证
        if (authenticationMethodSecurityConfig != null)
            authenticationMethodSecurityConfig.applyMethodAuthenticationConfig(http);

        //配置app环境下需要添加的认证内容
        http.apply(validateCodeSecurityConfig)
                .and()
                    .apply(smsCodeAuthenticationSecurityConfig)
                .and()
                    .apply(socialSecurityConfig)
                .and()
                    .apply(openIdAuthenticationSecurityConfig)
                .and()
                    .csrf().disable();

        //调用所有模块的资源权限配置,添加如spring security安全配置中
        authorizeConfigManager.config(http.authorizeRequests());
    }

}