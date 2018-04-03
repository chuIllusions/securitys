# 系统可配置Bean说明
## 社交模块
### QQ
解绑与绑定成功视图的配置
实现AbstractBindingProcessor接口,实现自定义的信息返回处理逻辑,并在系统中生成名为`qqBindingView`的bean
### 微信
 解绑与绑定成功视图的配置
 实现AbstractBindingProcessor接口,实现自定义的信息返回处理逻辑,并在系统中生成名为`weixinBindingView`的bean
### 普通配置
1. 配置默认的社交绑定状态信息输出器
实现AbstractConnectionViewProcessor接口,生成可为spring 管理的bean
```java
    @Bean
	@ConditionalOnMissingBean(AbstractConnectionViewProcessor.class)
	public AbstractConnectionViewProcessor connectionViewProcessor(ObjectMapper objectMapper){
		DefaultConnectionViewProcessor processor = new DefaultConnectionViewProcessor(objectMapper);
		return processor;
	}
```
## 验证码
### 配置验证码生成器
1.实现ValidateCodeGenerator接口,自定义生成逻辑
2.生成bean名称的规范:
    图片验证码命名为:imageValidateCodeGenerator
    短信验证码命名为:smsValidateCodeGenerator
### 配置短信发送商
1.实现SmsCodeSender接口,自定义短信发送处理逻辑
2.生成为spring 管理的bean 即可

## 验证码存储
1.实现ValidateCodeRepository接口,自定义保存/获取/删除验证码的处理逻辑

## 登录成功/失败处理器
### 配置登录成功处理器
1.继承SavedRequestAwareAuthenticationSuccessHandler类,实现自定义登录成功处理逻辑
2.生成bean的命名为:turingAuthenticationSuccessHandler
### 配置登录失败处理器
1.继承SimpleUrlAuthenticationFailureHandler,实现自定义登录成功处理逻辑
2.生成bean的命名为:turingAuthenticationFailureHandler
### 配置退出登录处理器
1.实现LogoutSuccessHandler接口,自定义实现逻辑,并生成为spring管理的bean


