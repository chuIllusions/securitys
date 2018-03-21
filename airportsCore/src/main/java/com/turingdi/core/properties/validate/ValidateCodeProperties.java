package com.turingdi.core.properties.validate;

import com.turingdi.core.properties.validate.code.ImageCodeProperties;
import com.turingdi.core.properties.validate.code.SmsCodeProperties;

/**
 * 所有验证码类型属性分类
 *
 * created by chuIllusions_tan 20180308
 */
public class ValidateCodeProperties {

    private ImageCodeProperties image = new ImageCodeProperties();

    private SmsCodeProperties sms = new SmsCodeProperties();

    public ImageCodeProperties getImage() {
        return image;
    }

    public void setImage(ImageCodeProperties image) {
        this.image = image;
    }

    public SmsCodeProperties getSms() {
        return sms;
    }

    public void setSms(SmsCodeProperties sms) {
        this.sms = sms;
    }
}
