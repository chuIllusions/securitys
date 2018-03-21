/**
 * 
 */
package com.turingdi.core.social.qq.config;

import com.turingdi.core.properties.SecurityProperties;
import com.turingdi.core.properties.social.qq.QQProperties;
import com.turingdi.core.social.qq.connect.QQConnectionFactory;
import com.turingdi.core.social.view.AbstractConnectView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.social.SocialAutoConfigurerAdapter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.social.connect.ConnectionFactory;
import org.springframework.social.connect.ConnectionFactoryLocator;
import org.springframework.social.connect.UsersConnectionRepository;
import org.springframework.web.servlet.View;

/**
 * QQ配置
 * ConditionalOnProperty：当系统中存在指定的配置时，此配置才生效
 *
 * created by chuIllusions_tan 20180302
 */
@Configuration
@ConditionalOnProperty(prefix = "turing.security.social.qq", name = "app-id")
public class QQAutoConfig extends SocialAutoConfigurerAdapter {

	@Autowired
	private SecurityProperties securityProperties;

	@Override
	protected ConnectionFactory<?> createConnectionFactory() {
		QQProperties qqConfig = securityProperties.getSocial().getQq();
		return new QQConnectionFactory(qqConfig.getProviderId(), qqConfig.getAppId(), qqConfig.getAppSecret());
	}

	/**
	 * 为了解决生产多个连接工厂，覆盖父类的连接工厂创建
	 * @param connectionFactoryLocator
	 * @return
	 */
	@Override
	public UsersConnectionRepository getUsersConnectionRepository(ConnectionFactoryLocator connectionFactoryLocator) {
		return null;
	}

	@Bean({"connect/qqConnect", "connect/qqConnected"})
	@ConditionalOnMissingBean(name = "qqConnectedView")
	public View qqConnectedView() {
		return new AbstractConnectView();
	}
}
