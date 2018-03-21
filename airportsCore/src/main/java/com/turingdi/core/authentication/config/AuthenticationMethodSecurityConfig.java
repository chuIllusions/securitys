package com.turingdi.core.authentication.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 系统认证方式基础实现配置接口
 * 认证方式包括：表单认证,basic认证
 *
 * created by chuIllusion_tan on 20180308
 */
public interface AuthenticationMethodSecurityConfig {

    void applyMethodAuthenticationConfig(HttpSecurity http) throws Exception;

}
