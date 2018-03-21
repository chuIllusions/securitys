package com.turingdi.browser.controller;

import com.turingdi.core.properties.SecurityConstants;
import com.turingdi.core.properties.SecurityProperties;
import com.turingdi.core.support.SimpleResponse;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * 访问权限控制层
 * created by chuIllusions_tan on 20180227.
 */

@RestController
public class BrowserSecurityController {
    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private SecurityProperties securityProperties;

    private RequestCache requestCache = new HttpSessionRequestCache();

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /**
     * 当需要身份认证时，跳转到这里
     * 处理：如果是页面请求则跳转到登录页面，如果是非页面请求则返回json数据响应
     * @param request 请求体
     * @param response 响应体
     * @return 跳转 or 返回状态信息
     * @throws IOException
     *
     * created by chuIllusions_tan 20180227
     */
    @RequestMapping(SecurityConstants.DEFAULT_UNAUTHENTICATION_URL)
    @ResponseStatus(code = HttpStatus.UNAUTHORIZED)
    public SimpleResponse requireAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest != null) {
            //获取请求头信息中数据响应返回类型
            List<String> values = savedRequest.getHeaderValues(securityProperties.getBrowser().getRequestTypeName());
            //是否符合是跳转到登录页面
            if (values.size()==0 || !securityProperties.getBrowser().getRequestTypeValue().equals(values.get(0))) {
                redirectStrategy.sendRedirect(request, response, securityProperties.getBrowser().getLoginPage());
            }
        }
        return new SimpleResponse("访问的服务需要身份认证，请引导用户到登录页");
    }

    /**
     * 返回当前用户信息
     * @return
     *
     * created by chuIllusions_tan 20180228
     */
    @GetMapping("/user/me")
    public Object getCurrentUser(){
        return SecurityContextHolder.getContext().getAuthentication();
    }


}
