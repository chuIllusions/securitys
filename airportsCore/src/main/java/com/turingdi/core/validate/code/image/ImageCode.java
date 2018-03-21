/**
 * 
 */
package com.turingdi.core.validate.code.image;

import com.turingdi.core.validate.code.common.ValidateCode;

import java.awt.image.BufferedImage;
import java.time.LocalDateTime;


/**
 * 图片验证码
 * created by chuIllusions_tan 20180228
 *
 */
public class ImageCode extends ValidateCode {

	private BufferedImage image;
	
	public ImageCode(BufferedImage image, String code, int expireIn){
		super(code,expireIn);
		this.image = image;
	}
	
	public ImageCode(BufferedImage image, String code, LocalDateTime expireTime){
		super(code,expireTime);
		this.image = image;
	}

	public BufferedImage getImage() {
		return image;
	}

	public void setImage(BufferedImage image) {
		this.image = image;
	}

	
}
