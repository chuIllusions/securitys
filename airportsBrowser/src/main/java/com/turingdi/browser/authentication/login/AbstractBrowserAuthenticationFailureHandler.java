package com.turingdi.browser.authentication.login;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.turingdi.core.properties.SecurityConstants;
import com.turingdi.core.properties.SecurityProperties;
import com.turingdi.core.support.SimpleResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录失败处理器
 *
 * created by chuIllusions_tan on 20180308
 */
public class AbstractBrowserAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private Logger logger = LoggerFactory.getLogger(getClass());

    private ObjectMapper objectMapper;

    private SecurityProperties securityProperties;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        logger.info("登录失败");

        //从请求头中获取是否含有指定响应类型的信息
        String requestType = request.getHeader(SecurityConstants.DEFAULT_JOSN_RESPONSE_HEADER_TYPE);

        if (requestType != null && SecurityConstants.DEFAULT_JOSN_RESPONSE_HEADER_TYPE_VALUES.equalsIgnoreCase(requestType)) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(objectMapper.writeValueAsString(new SimpleResponse(exception.getMessage())));
        }else{
            //默认处理
            super.onAuthenticationFailure(request, response, exception);
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

