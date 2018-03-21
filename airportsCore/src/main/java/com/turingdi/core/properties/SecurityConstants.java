package com.turingdi.core.properties;

/**
 * 系统默认常量配置
 *
 * created by chuIllusions_tan on 20180227.
 */
public interface SecurityConstants {

    /**
     * 当请求需要身份认证时，默认跳转的url
     */
    String DEFAULT_UNAUTHENTICATION_URL = "/authentication/require";

    /**
     * 默认用户名密码登录页面
     */
    String DEFAULT_LOGIN_PAGE_URL = "/templates/default-login.html";

    /**
     * 默认的用户名密码登录，请求处理url
     */
    String DEFAULT_LOGIN_PROCESSING_URL_FORM = "/authentication/form";

    /**
     * 默认的手机验证码登录请求处理url
     */
    String DEFAULT_LOGIN_PROCESSING_URL_MOBILE = "/authentication/mobile";

    /**
     * 默认的处理验证码的url前缀
     */
    String DEFAULT_VALIDATE_CODE_URL_PREFIX = "/code";

    /**
     * session失效默认的跳转地址
     */
    String DEFAULT_SESSION_INVALID_URL = "/session/invalid";

    /**
     * App环境下默认的社交登陆注册地址
     */
    String DEFAULT_APP_SOCIAL_SIGN_UP_URL = "/social/signUp";

    /**
     * 要求返回数据格式，请求头名称
     * 默认情况下不含该请求头返回text/html格式
     *
     */
    String DEFAULT_JOSN_RESPONSE_HEADER_TYPE = "request-type";

    /**
     * 若请求头中带有"request-type"参数,bi
     */
    String DEFAULT_JOSN_RESPONSE_HEADER_TYPE_VALUES = "json";

    /**
     * 验证图片验证码时，http请求中默认的携带图片验证码信息的参数的名称
     */
    String DEFAULT_PARAMETER_NAME_CODE_IMAGE = "imageCode";

    /**
     * 验证短信验证码时，http请求中默认的携带短信验证码信息的参数的名称
     */
    String DEFAULT_PARAMETER_NAME_CODE_SMS = "smsCode";

    /**
     * 发送短信验证码 或 验证短信验证码时，传递手机号的参数的名称
     */
    String DEFAULT_PARAMETER_NAME_MOBILE = "mobile";

    /**
     * SpringSocialConfigurer Bean的名字
     */
    String DEFAULT_SPRING_SOCIAL_CONFIGURER_BEAN_NAME = "abstractSpringSocialConfigurer";

    /**
     * jwt token key 默认值
     */
    String DEFAULT_JWT_KEY = "turing";


    /**
     * openid参数名
     */
    String DEFAULT_PARAMETER_NAME_OPENID = "openId";

    /**
     * providerId参数名
     */
    String DEFAULT_PARAMETER_NAME_PROVIDERID = "providerId";

    /**
     * 默认的OPENID登录请求处理url
     */
    String DEFAULT_LOGIN_PROCESSING_URL_OPENID = "/authentication/openid";

}
