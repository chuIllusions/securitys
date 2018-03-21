/**
 * 
 */
package com.turingdi.core.social.qq.connect;


import com.turingdi.core.social.qq.api.QQ;
import org.springframework.social.connect.support.OAuth2ConnectionFactory;

/**
 * 构造ConnectionFactory
 * 继承<T> T：指当前的适配器 是 适配哪个 API
 * created by chuIllusions_tan 20180302
 */
public class QQConnectionFactory extends OAuth2ConnectionFactory<QQ> {

	public QQConnectionFactory(String providerId, String appId, String appSecret) {
		super(providerId, new QQServiceProvider(appId, appSecret), new QQAdapter());
	}

}
