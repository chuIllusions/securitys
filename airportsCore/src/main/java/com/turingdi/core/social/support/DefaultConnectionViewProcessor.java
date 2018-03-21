package com.turingdi.core.social.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.social.connect.Connection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 默认提供的输出社交绑定信息的实现类
 *
 * created by chuIllusions_tan on 20180308
 */
public class DefaultConnectionViewProcessor implements AbstractConnectionViewProcessor {

    private ObjectMapper objectMapper;

    public DefaultConnectionViewProcessor(ObjectMapper objectMapper){
        this.objectMapper = objectMapper;
    }

    @Override
    public void outputModel(Map<String, Object> model, HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, List<Connection<?>>> connections = (Map<String, List<Connection<?>>>) model.get("connectionMap");

        Map<String, Boolean> result = new HashMap<>();
        for (String key : connections.keySet()) {
            result.put(key, CollectionUtils.isNotEmpty(connections.get(key)));
        }

        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(result));
    }

}
