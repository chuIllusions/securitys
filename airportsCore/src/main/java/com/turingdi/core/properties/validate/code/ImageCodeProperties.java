/**
 * 
 */
package com.turingdi.core.properties.validate.code;

/**
 * 图形验证码属性
 *
 * created by chuIllusions_tan 20180228
 */
public class ImageCodeProperties extends CodeProperties{

	//验证码的默认长度与高度
	private int width = 67;
	private int height = 23;
	
	public int getWidth() {
		return width;
	}
	public void setWidth(int width) {
		this.width = width;
	}
	public int getHeight() {
		return height;
	}
	public void setHeight(int height) {
		this.height = height;
	}

}
