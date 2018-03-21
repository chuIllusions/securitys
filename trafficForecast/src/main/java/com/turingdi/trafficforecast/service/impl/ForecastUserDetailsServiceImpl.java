package com.turingdi.trafficforecast.service.impl;

import com.turingdi.trafficforecast.entity.SystemUser;
import com.turingdi.trafficforecast.mapper.UserMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.social.security.SocialUser;
import org.springframework.social.security.SocialUserDetails;
import org.springframework.social.security.SocialUserDetailsService;
import org.springframework.stereotype.Service;

/**
 * 自定义实现 spring security 验证逻辑
 * created by chuIllusions_tan on 2018/2/27.
 */
@Service
public class ForecastUserDetailsServiceImpl implements UserDetailsService,SocialUserDetailsService {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //spring security框架提供的一个实现了UserDetails接口的实现类
        //dao查询username信息
        SystemUser user = userMapper.findSystemUserByUsername(username);
        if (user == null){
            //AbstractUserDetailsAuthenticationProvider把UsernameNotFoundException包装其他异常，因为AbstractUserDetailsAuthenticationProvider.hideUserNotFoundExceptions=true
            throw new UsernameNotFoundException("无法找到用户名为:" + username + "的用户");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        //三个参数:username,password,authorities：授权
        //分割String类型为授权集合
        return new User(username,user.getPassword(), AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }

    @Override
    public SocialUserDetails loadUserByUserId(String userId) throws UsernameNotFoundException {
        SystemUser user = userMapper.findSystemUserByUsername(userId);
        if (user == null){
            //AbstractUserDetailsAuthenticationProvider把UsernameNotFoundException包装其他异常，因为AbstractUserDetailsAuthenticationProvider.hideUserNotFoundExceptions=true
            throw new UsernameNotFoundException("无法找到用户名为:" + userId + "的用户");
        }
        return new SocialUser(userId,user.getPassword(),AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
