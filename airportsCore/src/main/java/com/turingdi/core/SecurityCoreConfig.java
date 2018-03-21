/**
 * 
 */
package com.turingdi.core;

import com.turingdi.core.properties.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 开启配置
 * @EnableConfigurationProperties(SecurityProperties.class) //使指定的配置类生效
 *
 * created by chuIllusions_tan 20180227
 */
@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityCoreConfig {

    /**
     * 配置一个PasswordEncoder加密的实现类
     * 可以自定义加密类如使用MD5、SHA1等实现加密逻辑然后实现PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
