package com.turingdi.core.authentication.config;

import com.turingdi.core.properties.SecurityConstants;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * 抽象的spring security 配置。 默认使用表单进行登录
 * WebSecurityConfigurerAdapter: Spring Security 在web应用上配置适配器
 *
 * created by chuIllusions_tan on 20180227
 */
public class AbstractAuthenticationMethodSecurityConfig implements AuthenticationMethodSecurityConfig{

    private AuthenticationFailureHandler authenticationFailureHandler;

    private AuthenticationSuccessHandler authenticationSuccessHandler;

    public AbstractAuthenticationMethodSecurityConfig(AuthenticationSuccessHandler authenticationSuccessHandler, AuthenticationFailureHandler authenticationFailureHandler){
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    /**
     * 使用表单登录作为认证方式
     * @param http 全局安全配置
     * @throws Exception
     */
    @Override
    public void applyMethodAuthenticationConfig(HttpSecurity http) throws Exception {
        //最简单的配置
        //http.httpBasic()//使用httpbasic验证，spring security 默认使用
        http.formLogin() //开启使用表单验证
                .loginPage(SecurityConstants.DEFAULT_UNAUTHENTICATION_URL)//配置登录请求处理
                .loginProcessingUrl(SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_FORM)//处理登录请求
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler);
    }
}
