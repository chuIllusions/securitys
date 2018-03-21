/**
 * 
 */
package com.turingdi.core.social.qq.connect;

import com.turingdi.core.social.qq.api.QQ;
import com.turingdi.core.social.qq.api.QQImpl;
import org.springframework.social.oauth2.AbstractOAuth2ServiceProvider;

/**
 * QQ Provider 需要实现 AbstractOAuth2ServiceProvider<T> T：传入QQ API类型
 * created by chuIllusions_tan 20180302
 */
public class QQServiceProvider extends AbstractOAuth2ServiceProvider<QQ> {

	private String appId;

	//导向认证地址，获取授权码
	private static final String URL_AUTHORIZE = "https://graph.qq.com/oauth2.0/authorize";

	//拿着授权码获取令牌申请地址
	private static final String URL_ACCESS_TOKEN = "https://graph.qq.com/oauth2.0/token";
	
	public QQServiceProvider(String appId, String appSecret) {
		//单例
		super(new QQOAuth2Template(appId, appSecret, URL_AUTHORIZE, URL_ACCESS_TOKEN));
		this.appId = appId;
		
	}
	
	@Override
	public QQ getApi(String accessToken) {
		return new QQImpl(accessToken, appId);
	}

}
