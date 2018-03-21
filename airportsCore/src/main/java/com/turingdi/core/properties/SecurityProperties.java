package com.turingdi.core.properties;

import com.turingdi.core.properties.browser.BrowserProperties;
import com.turingdi.core.properties.oauth.OAuth2Properties;
import com.turingdi.core.properties.social.SocialProperties;
import com.turingdi.core.properties.validate.ValidateCodeProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 核心配置属性
 * 依据配置文件中turing.security进行属性配置
 *
 * Created by chuIllusions_tan on 2018/2/27.
 */
@ConfigurationProperties(prefix = "turing.security")
public class SecurityProperties {

    /**
     * 浏览器相关配置，配置名为turing.security.browser
     */
    private BrowserProperties browser = new BrowserProperties();

    /**
     * 配置验证码配置,配置名:turing.security.code
     */
    private ValidateCodeProperties code = new ValidateCodeProperties();

    /**
     * 社交登陆的相关配置,配置名:turing.security.social
     */
    private SocialProperties social = new SocialProperties();

    /**
     * Oauth 认证服务器相关配置,配置名:turing.security.oauth2
     */
    private OAuth2Properties oauth2 = new OAuth2Properties();

    public ValidateCodeProperties getCode() {
        return code;
    }

    public void setCode(ValidateCodeProperties code) {
        this.code = code;
    }

    public BrowserProperties getBrowser() {
        return browser;
    }

    public void setBrowser(BrowserProperties browser) {
        this.browser = browser;
    }

    public SocialProperties getSocial() {
        return social;
    }

    public void setSocial(SocialProperties social) {
        this.social = social;
    }

    public OAuth2Properties getOauth2() {
        return oauth2;
    }

    public void setOauth2(OAuth2Properties oauth2) {
        this.oauth2 = oauth2;
    }
}
