/**
 * 
 */
package com.turingdi.browser.session;

import java.io.IOException;

import javax.servlet.ServletException;

import com.turingdi.core.properties.SecurityProperties;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

/**
 * 并发登录导致session失效时，默认的处理策略
 * 
 * created by chuIllusions_tan on 20180308
 *
 */
public class AbstractExpiredSessionStrategy extends AbstractSessionStrategy implements SessionInformationExpiredStrategy {

	public AbstractExpiredSessionStrategy(SecurityProperties securityPropertie) {
		super(securityPropertie);
	}


	@Override
	public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
		onSessionInvalid(event.getRequest(), event.getResponse());
	}
	

	@Override
	protected boolean isConcurrency() {
		return true;
	}

}
