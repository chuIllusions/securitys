/**
 * 
 */
package com.turingdi.core.social.view;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.turingdi.core.social.support.AbstractConnectionViewProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.AbstractView;

/**
 * 社交账号绑定状态视图
 *
 * created by chuIllusions_tan on 20180308
 */
@Component("connect/status")
public class AbstractConnectionStatusView extends AbstractView {
	
	@Autowired
	private AbstractConnectionViewProcessor abstractConnectionViewProcessor;

	@SuppressWarnings("unchecked")
	@Override
	protected void renderMergedOutputModel(Map<String, Object> model, HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		abstractConnectionViewProcessor.outputModel(model,request,response);
	}

}
