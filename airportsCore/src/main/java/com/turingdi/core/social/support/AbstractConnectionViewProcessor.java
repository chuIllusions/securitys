package com.turingdi.core.social.support;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * 为扩展提供spring 社交绑定状态信息返回提供接口
 * 各个模块可实现该接口逻辑进行状态信息的输出
 *
 * created by chuIllusions_tan on 20180308
 */
public interface AbstractConnectionViewProcessor {

    /**
     * 实现社交绑定状态信息（内容自定义）的输出
     * @param model spring social 在ConnectController内存将此属性填充,含有属性:providerIds、connectionMap等，我们只需要用就可以了
     * @param request 请求体
     * @param response 响应体
     */
    void outputModel(Map<String, Object> model, HttpServletRequest request,HttpServletResponse response) throws IOException;

}
