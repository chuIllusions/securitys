/**
 * 
 */
package com.turingdi.app.social;

import com.turingdi.core.properties.SecurityConstants;
import com.turingdi.core.social.support.AbstractSpringSocialConfigurer;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.stereotype.Component;

/**
 * 针对在APP配置中 当 SpringSocialConfigurer 初始化之后
 * 更改注册地址
 */
@Component
public class SpringSocialConfigurerPostProcessor implements BeanPostProcessor {

	@Override
	public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
		return bean;
	}

	/**
	 * 符合为spring social configurer bean 则进行社交社交注册地址更改
	 */
	@Override
	public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
		if (StringUtils.equals(beanName, SecurityConstants.DEFAULT_SPRING_SOCIAL_CONFIGURER_BEAN_NAME)) {
			AbstractSpringSocialConfigurer configurer = (AbstractSpringSocialConfigurer)bean;
			configurer.signupUrl(SecurityConstants.DEFAULT_APP_SOCIAL_SIGN_UP_URL);
			return configurer;
		}
		return bean;
	}

}
