package com.turingdi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.support.SpringBootServletInitializer;

/**
 * 人流预测系统入口
 * 入口类继承SpringBootServletInitializer，覆盖其configure方法即可监听war包中的启动类
 * created by chuIllusions_tan on 20180227.
 */

@SpringBootApplication
public class TrafficForecastEntryApplication extends SpringBootServletInitializer {

    public TrafficForecastEntryApplication() {
    }

    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(new Class[]{TrafficForecastEntryApplication.class});
    }


    public static void main(String[] args) {
        SpringApplication.run(TrafficForecastEntryApplication.class, args);
    }
}
