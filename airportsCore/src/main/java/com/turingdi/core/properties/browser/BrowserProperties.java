package com.turingdi.core.properties.browser;

import com.turingdi.core.properties.SecurityConstants;

/**
 * 浏览器属性默认配置
 *
 * created by chuIllusions_tan on 20180227.
 */
public class BrowserProperties {

    private String loginPage = SecurityConstants.DEFAULT_LOGIN_PAGE_URL;

    private String requestTypeName = SecurityConstants.DEFAULT_JOSN_RESPONSE_HEADER_TYPE;

    private String requestTypeValue = SecurityConstants.DEFAULT_JOSN_RESPONSE_HEADER_TYPE_VALUES;

    private SessionProperties session = new SessionProperties();

    /**
     * '记住我'功能的有效时间，默认1小时
     */
    private int rememberMeSeconds = 3600;

    private String signUpUrl = "/turing-sign.html";

    private String signOutUrl;

    /**
     * 登录成功后跳转的地址，如果设置了此属性，则登录成功后总是会跳到这个地址上。
     *
     * 只在signInResponseType为REDIRECT时生效
     */
    private String singInSuccessUrl;


    public String getLoginPage() {
        return loginPage;
    }

    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }

    public String getRequestTypeName() {
        return requestTypeName;
    }

    public void setRequestTypeName(String requestTypeName) {
        this.requestTypeName = requestTypeName;
    }

    public String getRequestTypeValue() {
        return requestTypeValue;
    }

    public void setRequestTypeValue(String requestTypeValue) {
        this.requestTypeValue = requestTypeValue;
    }

    public SessionProperties getSession() {
        return session;
    }

    public void setSession(SessionProperties session) {
        this.session = session;
    }

    public String getSignUpUrl() {
        return signUpUrl;
    }

    public void setSignUpUrl(String signUpUrl) {
        this.signUpUrl = signUpUrl;
    }

    public String getSignOutUrl() {
        return signOutUrl;
    }

    public void setSignOutUrl(String signOutUrl) {
        this.signOutUrl = signOutUrl;
    }

    public String getSingInSuccessUrl() {
        return singInSuccessUrl;
    }

    public void setSingInSuccessUrl(String singInSuccessUrl) {
        this.singInSuccessUrl = singInSuccessUrl;
    }

    public int getRememberMeSeconds() {
        return rememberMeSeconds;
    }

    public void setRememberMeSeconds(int rememberMeSeconds) {
        this.rememberMeSeconds = rememberMeSeconds;
    }
}
