/**
 * 
 */
package com.turingdi.core.authorize;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;

/**
 * 授权信息管理器接口
 * 用于收集系统中所有 AuthorizeConfigProvider 并加载其配置
 *
 * created by chuIllusions_tan 20180308
 *
 */
public interface AuthorizeConfigManager {
	
	void config(ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry config);

}
