/**
 * 
 */
package com.turingdi.core.social.support;

import org.springframework.social.security.SocialAuthenticationFilter;

/**
 * 定义后处理器接口，处理不同模式下授权后返回的信息
 * 如果不进行配置，则不修改SocialAuthenticationFilter里的任何属性值
 * 默认不进行设置，即没有实现类
 *
 * created by chuIllusions_tan 20180305
 */
public interface SocialAuthenticationFilterPostProcessor {
	
	void process(SocialAuthenticationFilter socialAuthenticationFilter);

}
