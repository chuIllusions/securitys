/**
 * 
 */
package com.turingdi.core.social.view;

import com.turingdi.core.social.support.AbstractBindingProcessor;
import org.springframework.web.servlet.view.AbstractView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * spring security 处理第三方登陆解绑与绑定返回结果视图
 *
 * created by chuIllusions_tan on 20180308
 */
public class AbstractConnectBindingView extends AbstractView {

	private AbstractBindingProcessor abstractBindingProcessor;

	public AbstractConnectBindingView(AbstractBindingProcessor abstractBindingProcessor){
		this.abstractBindingProcessor = abstractBindingProcessor;
	}

	@Override
	protected void renderMergedOutputModel(Map<String, Object> model, HttpServletRequest request,
			HttpServletResponse response) throws Exception {

		abstractBindingProcessor.outputModel(model,request,response);

	}

}
