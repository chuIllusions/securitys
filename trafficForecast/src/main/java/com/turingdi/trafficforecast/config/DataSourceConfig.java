package com.turingdi.trafficforecast.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;

/**
 * 实现自定义数据源配置
 * created by chuIllusions_tan on 20180228.
 */
@Configuration
@MapperScan(basePackages = "com.turingdi.trafficforecast.mapper")
public class DataSourceConfig {
}
