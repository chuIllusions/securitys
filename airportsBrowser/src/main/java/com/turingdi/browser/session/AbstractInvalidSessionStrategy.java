/**
 * 
 */
package com.turingdi.browser.session;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.turingdi.core.properties.SecurityProperties;
import org.springframework.security.web.session.InvalidSessionStrategy;

/**
 * 默认的session失效处理策略
 * 
 * created by chuIllusions_tan on 20180308
 *
 */
public class AbstractInvalidSessionStrategy extends AbstractSessionStrategy implements InvalidSessionStrategy {

	public AbstractInvalidSessionStrategy(SecurityProperties securityProperties) {
		super(securityProperties);
	}

	@Override
	public void onInvalidSessionDetected(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		onSessionInvalid(request, response);
	}

}
