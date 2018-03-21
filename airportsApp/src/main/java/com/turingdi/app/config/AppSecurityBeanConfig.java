package com.turingdi.app.config;

import com.turingdi.core.authentication.config.AbstractAuthenticationMethodSecurityConfig;
import com.turingdi.core.authentication.config.AuthenticationMethodSecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.sql.DataSource;

/**
 * app环境下的bean配置
 *
 * created by chuIllusions_tan 20180309
 */
@Configuration
public class AppSecurityBeanConfig {

    @Autowired
    private AuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private AuthenticationSuccessHandler authenticationSuccessHandler;

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

}
