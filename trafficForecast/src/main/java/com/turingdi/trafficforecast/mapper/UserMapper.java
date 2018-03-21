package com.turingdi.trafficforecast.mapper;

import com.turingdi.trafficforecast.entity.SystemUser;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

/**
 * created by chuIllusions_tan on 20180228.
 */
public interface UserMapper {

    @Select("SELECT * FROM t_user WHERE USERNAME = #{username}")
    SystemUser findSystemUserByUsername(@Param("username") String username);

}
