package com.turingdi.core.social.support;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * 默认的绑定与解绑处理器实现类
 *
 * created by chuIllusions_tan 20180322
 */

public class DefaultBindingProcessor implements AbstractBindingProcessor {

    @Override
    public void outputModel(Map<String, Object> model, HttpServletRequest request, HttpServletResponse response) throws IOException {

        response.setContentType("text/html;charset=UTF-8");
        if (model.get("connections") == null) {
            response.getWriter().write("<h3>解绑成功</h3>");
        } else {
            response.getWriter().write("<h3>绑定成功</h3>");
        }

    }

}
