/**
 * 
 */
package com.turingdi.core.social.qq.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.social.oauth2.AbstractOAuth2ApiBinding;
import org.springframework.social.oauth2.TokenStrategy;

/**
 * 用户获取QQ 用户信息
 * QQ API 实现类
 * 所有的API需要继承 AbstractOAuth2ApiBinding 提供access_token属性  RestTemplate用户发送HTTP请求
 * 多例对象，每个用户都拥有一个QQImpl实例
 * created by chuIllusions_tan 20180302
 */
public class QQImpl extends AbstractOAuth2ApiBinding implements QQ {

	private Logger logger = LoggerFactory.getLogger(this.getClass());

	//qq根据access_token(令牌)获取openId
	private static final String URL_GET_OPENID = "https://graph.qq.com/oauth2.0/me?access_token=%s";

	//获取用户信息
	private static final String URL_GET_USERINFO = "https://graph.qq.com/user/get_user_info?oauth_consumer_key=%s&openid=%s";
	
	private String appId;
	
	private String openId;

	private ObjectMapper objectMapper = new ObjectMapper();

	//走完oAuth协议获取到的accessToken
	public QQImpl(String accessToken, String appId) {
		//设置策略，发送请求时，token以参数形式在请求地址中
		super(accessToken, TokenStrategy.ACCESS_TOKEN_PARAMETER);
		
		this.appId = appId;
		
		String url = String.format(URL_GET_OPENID, accessToken);
		String result = getRestTemplate().getForObject(url, String.class);
		
		logger.info(result);

		this.openId = StringUtils.substringBetween(result, "\"openid\":\"", "\"}");
	}

	@Override
	public QQUserInfo getUserInfo(){

		String url = String.format(URL_GET_USERINFO, appId, openId);
		String result = getRestTemplate().getForObject(url, String.class);

		logger.info(result);

		QQUserInfo userInfo = null;
		try {
			userInfo = objectMapper.readValue(result, QQUserInfo.class);
			userInfo.setOpenId(openId);
			return userInfo;
		} catch (Exception e) {
			throw new RuntimeException("获取用户信息失败", e);
		}
	}
}
