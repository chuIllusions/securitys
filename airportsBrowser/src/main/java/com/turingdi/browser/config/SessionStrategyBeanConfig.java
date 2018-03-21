package com.turingdi.browser.config;

import com.turingdi.browser.session.AbstractExpiredSessionStrategy;
import com.turingdi.browser.session.AbstractInvalidSessionStrategy;
import com.turingdi.core.properties.SecurityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

/**
 * session管理策略相关的扩展点配置。配置在这里的bean，业务系统都可以通过声明同类型或同名的bean来覆盖安全
 * 模块默认的配置。
 *
 * created by chuIllusions_tan 20180308
 */
@Configuration
public class SessionStrategyBeanConfig {

    @Autowired
    private SecurityProperties securityProperties;

    /**
     * session失效时的处理策略配置
     * @return
     */
    @Bean
    @ConditionalOnMissingBean(InvalidSessionStrategy.class)
    public InvalidSessionStrategy invalidSessionStrategy(){
        return new AbstractInvalidSessionStrategy(securityProperties);
    }

    /**
     * 并发登录导致前一个session失效时的处理策略配置
     * @return
     */
    @Bean
    @ConditionalOnMissingBean(SessionInformationExpiredStrategy.class)
    public SessionInformationExpiredStrategy sessionInformationExpiredStrategy(){
        return new AbstractExpiredSessionStrategy(securityProperties);
    }


}
