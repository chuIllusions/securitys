/**
 * 
 */
package com.turingdi.core.properties.social;

import com.turingdi.core.properties.social.qq.QQProperties;
import com.turingdi.core.properties.social.weixin.WeixinProperties;

/**
 * 社交登陆配置
 * created by chuIllusions_tan 20180302
 */
public class SocialProperties {

	private QQProperties qq = new QQProperties();

	private WeixinProperties weixin = new WeixinProperties();

	private String filterProcessesUrl = "/auth";

	public QQProperties getQq() {
		return qq;
	}

	public void setQq(QQProperties qq) {
		this.qq = qq;
	}

	public String getFilterProcessesUrl() {
		return filterProcessesUrl;
	}

	public void setFilterProcessesUrl(String filterProcessesUrl) {
		this.filterProcessesUrl = filterProcessesUrl;
	}

	public WeixinProperties getWeixin() {
		return weixin;
	}

	public void setWeixin(WeixinProperties weixin) {
		this.weixin = weixin;
	}
}
