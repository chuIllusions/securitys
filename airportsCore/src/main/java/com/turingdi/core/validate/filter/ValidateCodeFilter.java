/**
 * 
 */
package com.turingdi.core.validate.filter;

import com.turingdi.core.properties.SecurityConstants;
import com.turingdi.core.properties.SecurityProperties;
import com.turingdi.core.validate.code.common.ValidateCodeException;
import com.turingdi.core.validate.code.common.ValidateCodeProcessorHolder;
import com.turingdi.core.validate.code.common.ValidateCodeType;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * 生成过滤器，负责对验证码进行校验
 * InitializingBean:初始化bean后完成一些指定的业务处理逻辑
 * OncePerRequestFilter:在spring中，filter都默认继承OncePerRequestFilter,确保在一次请求只通过一次filter，而不需要重复执行
 *
 * created by chuIllusions_tan 20180308
 */
@Component("validateCodeFilter")
public class ValidateCodeFilter extends OncePerRequestFilter implements InitializingBean {

	/**
	 * 验证码校验失败处理器
	 */

	@Autowired
	private AuthenticationFailureHandler authenticationFailureHandler;

	/**
	 * 系统配置信息
	 */
	@Autowired
	private SecurityProperties securityProperties;

	/**
	 * 系统中的校验码处理器
	 */
	@Autowired
	private ValidateCodeProcessorHolder validateCodeProcessorHolder;

	/**
	 * 存放所有需要校验验证码的url
	 */
	private Map<String, ValidateCodeType> urlMap = new HashMap<>();

	/**
	 * 验证请求url与配置的url是否匹配的工具类
	 */
	private AntPathMatcher pathMatcher = new AntPathMatcher();

	/**
	 * 初始化要拦截的url配置信息
	 */
	@Override
	public void afterPropertiesSet() throws ServletException {
		super.afterPropertiesSet();

		//从系统中读取信息，放入不同的类型
		urlMap.put(SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_FORM, ValidateCodeType.IMAGE);
		addUrlToMap(securityProperties.getCode().getImage().getUrl(), ValidateCodeType.IMAGE);

		urlMap.put(SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_MOBILE, ValidateCodeType.SMS);
		addUrlToMap(securityProperties.getCode().getSms().getUrl(), ValidateCodeType.SMS);
	}

	/**
	 * 从系统中配置的需要校验验证码的URL根据校验的类型放入map
	 * 
	 * @param urlString 配置的url字符串,每条url用,分割
	 * @param type 验证码类型
	 */
	protected void addUrlToMap(String urlString, ValidateCodeType type) {
		if (StringUtils.isNotBlank(urlString)) {
			String[] urls = StringUtils.splitByWholeSeparatorPreserveAllTokens(urlString, ",");
			for (String url : urls) {
				urlMap.put(url, type);
			}
		}
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		ValidateCodeType type = getValidateCodeType(request);
		if (type != null) {
			logger.info("校验请求(" + request.getRequestURI() + ")中的验证码,验证码类型" + type);
			try {
				validateCodeProcessorHolder.findValidateCodeProcessor(type)
						.validate(new ServletWebRequest(request, response));
				logger.info("验证码校验通过");
			} catch (ValidateCodeException exception) {
				authenticationFailureHandler.onAuthenticationFailure(request, response, exception);
				return;
			}
		}

		chain.doFilter(request, response);

	}

	/**
	 * 获取校验码的类型，如果当前请求不需要校验，则返回null
	 * 
	 * @param request
	 * @return
	 */
	private ValidateCodeType getValidateCodeType(HttpServletRequest request) {
		ValidateCodeType result = null;
		if (!StringUtils.equalsIgnoreCase(request.getMethod(), "get")) {
			Set<String> urls = urlMap.keySet();
			for (String url : urls) {
				if (pathMatcher.match(url, request.getRequestURI())) {
					result = urlMap.get(url);
				}
			}
		}
		return result;
	}

}
