package com.turingdi.browser.authentication.login;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.turingdi.core.properties.SecurityConstants;
import com.turingdi.core.properties.SecurityProperties;
import com.turingdi.core.support.SimpleResponse;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Spring Security默认的处理登陆成功的机制是:登陆成功后，跳转到引发登陆的那个请求上（如：访问/user需要进行登陆，则跳到登陆页，当登陆成功后，再次跳转到/user）
 * AuthenticationSuccessHandler子类SavedRequestAwareAuthenticationSuccessHandler是默认的处理器（跳转到之前缓存器的那个请求）
 *
 * created by chuIllusions_tan on 20180308
 */
public class AbstractBrowserAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private Logger logger = LoggerFactory.getLogger(getClass());

    private ObjectMapper objectMapper;

    private SecurityProperties securityProperties;

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        logger.info("登录成功");
        response.setStatus(HttpStatus.OK.value());

        //从请求头中获取是否含有指定响应类型的信息
        String requestType = request.getHeader(SecurityConstants.DEFAULT_JOSN_RESPONSE_HEADER_TYPE);

        //登录是否需要json响应
        if (requestType != null && SecurityConstants.DEFAULT_JOSN_RESPONSE_HEADER_TYPE_VALUES.equalsIgnoreCase(requestType)) {
            response.setContentType("application/json;charset=UTF-8");
            String type = authentication.getClass().getSimpleName();
            response.getWriter().write(objectMapper.writeValueAsString(new SimpleResponse(type)));
        } else {
            // 如果设置了turing.security.browser.singInSuccessUrl，总是跳到设置的地址上
            // 如果没设置，则尝试跳转到登录之前访问的地址上，如果登录前访问地址为空，则跳到网站根路径上
            if (StringUtils.isNotBlank(securityProperties.getBrowser().getSingInSuccessUrl())) {
                requestCache.removeRequest(request, response);
                setAlwaysUseDefaultTargetUrl(true);
                setDefaultTargetUrl(securityProperties.getBrowser().getSingInSuccessUrl());
            }

            super.onAuthenticationSuccess(request, response, authentication);
        }

    }

    public ObjectMapper getObjectMapper() {
        return objectMapper;
    }

    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public SecurityProperties getSecurityProperties() {
        return securityProperties;
    }

    public void setSecurityProperties(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

}
