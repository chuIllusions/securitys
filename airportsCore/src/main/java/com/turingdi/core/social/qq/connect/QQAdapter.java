/**
 * 
 */
package com.turingdi.core.social.qq.connect;

import com.turingdi.core.social.qq.api.QQ;
import com.turingdi.core.social.qq.api.QQUserInfo;
import org.springframework.social.connect.ApiAdapter;
import org.springframework.social.connect.ConnectionValues;
import org.springframework.social.connect.UserProfile;

/**
 * 构造Adapter
 * 需要实现ApiAdapter<T> T：指当前的适配器 是 适配哪个 API
 * created by chuIllusions_tan 20180302
 */
public class QQAdapter implements ApiAdapter<QQ> {

	//服务是否为可用
	@Override
	public boolean test(QQ api) {
		return true;
	}

	/**
	 * Connection数据 与 Api 数据 的适配
	 * @param api
	 * @param values 创建Connection所需要的数据项
	 */
	@Override
	public void setConnectionValues(QQ api, ConnectionValues values) {
		QQUserInfo userInfo = api.getUserInfo();
		
		values.setDisplayName(userInfo.getNickname());
		values.setImageUrl(userInfo.getFigureurl_qq_1());
		values.setProfileUrl(null);//个人主页，QQ没有。微博就会有
		values.setProviderUserId(userInfo.getOpenId());
	}

	@Override
	public UserProfile fetchUserProfile(QQ api) {
		return null;
	}

	@Override
	public void updateStatus(QQ api, String message) {
	}

}
