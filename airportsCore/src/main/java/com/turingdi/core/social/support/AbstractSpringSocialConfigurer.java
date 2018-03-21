/**
 * 
 */
package com.turingdi.core.social.support;

import org.springframework.social.security.SocialAuthenticationFilter;
import org.springframework.social.security.SpringSocialConfigurer;

/**
 * 自定义配置SocialConfigurer,覆盖其默认拍配置
 * 作用：SocialAuthenticationFilter初始化完成后，重新设置它的某些属性
 *
 * created by chuIllusions_tan 20180302
 */
public class AbstractSpringSocialConfigurer extends SpringSocialConfigurer {
	
	private String filterProcessesUrl;//实现可配置的社交登陆拦截url

	private SocialAuthenticationFilterPostProcessor socialAuthenticationFilterPostProcessor;
	
	public AbstractSpringSocialConfigurer(String filterProcessesUrl) {
		this.filterProcessesUrl = filterProcessesUrl;
	}
	
	@Override
	protected <T> T postProcess(T object) {
		SocialAuthenticationFilter filter = (SocialAuthenticationFilter) super.postProcess(object);
		//设置社交登陆拦截的url
		filter.setFilterProcessesUrl(filterProcessesUrl);
		if (socialAuthenticationFilterPostProcessor != null) {
			//为SocialAuthenticationFilter增加额外的属性
			//在不同的项目下会有不同的实现
			socialAuthenticationFilterPostProcessor.process(filter);
		}
		return (T) filter;
	}

	public SocialAuthenticationFilterPostProcessor getSocialAuthenticationFilterPostProcessor() {
		return socialAuthenticationFilterPostProcessor;
	}

	public void setSocialAuthenticationFilterPostProcessor(SocialAuthenticationFilterPostProcessor socialAuthenticationFilterPostProcessor) {
		this.socialAuthenticationFilterPostProcessor = socialAuthenticationFilterPostProcessor;
	}

	public String getFilterProcessesUrl() {
		return filterProcessesUrl;
	}

	public void setFilterProcessesUrl(String filterProcessesUrl) {
		this.filterProcessesUrl = filterProcessesUrl;
	}
}
