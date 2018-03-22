package com.turingdi.core.social.support;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * 抽象的绑定成功与解绑成功信息回显处理器
 * 实现可扩展接口
 *
 *
 * created by chuIllusions_tan 20180322
 */
public interface AbstractBindingProcessor {


    /**
     * 实现社交绑定与解绑的信息输出
     * @param model 包含解绑和绑定成功后的一些信息
     * @param request 请求体
     * @param response 响应体
     */
    void outputModel(Map<String, Object> model, HttpServletRequest request, HttpServletResponse response) throws IOException;


}
