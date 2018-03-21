package com.turingdi.core.properties.validate.code;

/**
 * 验证码需要配置的基本属性
 *
 * created by chuIllusions_tan 20180308
 */
public class CodeProperties {

    private int length = 4;  //验证码基本长度
    private int expireIn = 60;//验证码的过期时间/秒

    private String url; //拦截url可配置化

    public int getLength() {
        return length;
    }
    public void setLength(int lenght) {
        this.length = lenght;
    }
    public int getExpireIn() {
        return expireIn;
    }
    public void setExpireIn(int expireIn) {
        this.expireIn = expireIn;
    }
    public String getUrl() {
        return url;
    }
    public void setUrl(String url) {
        this.url = url;
    }

}
