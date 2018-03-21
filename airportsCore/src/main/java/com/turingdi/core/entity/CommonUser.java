package com.turingdi.core.entity;

/**
 * 常用的用户实体
 * 包含基础信息，可扩展
 * created by chuIllusions_tan on 20180228
 */
public class CommonUser {
    private int id;
    private String username;
    private String password;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
