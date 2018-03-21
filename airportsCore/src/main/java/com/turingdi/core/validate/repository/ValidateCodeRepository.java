/**
 * 
 */
package com.turingdi.core.validate.repository;

import com.turingdi.core.validate.code.common.ValidateCode;
import com.turingdi.core.validate.code.common.ValidateCodeType;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * 验证码存储接口
 * 提供给不同类型的自定义实现，浏览器项目可用session ， app项目可用redis数据库等进行验证码的保存
 *
 * created by chuIllusions_tan 20180305
 */
public interface ValidateCodeRepository {

	/**
	 * 保存验证码
	 * @param request 请求
	 * @param code 验证码实体
	 * @param validateCodeType 验证码类型
	 */
	void save(ServletWebRequest request, ValidateCode code, ValidateCodeType validateCodeType);

	/**
	 * 获取验证码
	 * @param request 请求
	 * @param validateCodeType 验证码类型
	 * @return
	 */
	ValidateCode get(ServletWebRequest request, ValidateCodeType validateCodeType);

	/**
	 * 移除验证码
	 * @param request 请求
	 * @param codeType 验证码类型
	 */
	void remove(ServletWebRequest request, ValidateCodeType codeType);

}
