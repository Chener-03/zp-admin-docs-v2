---
title: 后端详解
icon: page
order: 1
date: 2023-03-31
category:
- 使用指南
tag:
- 源码解读
- 教程

---


> 本文档为后端文档，主要介绍后端的实现和使用方法。



## 鉴权
> 介绍：系统采用RBAC权限模型，RBAC 指的是基于角色的访问控制（Role-Based Access Control），
> 其中角色指的是一个或多个权限的集合，这些权限定义了一个用户可以执行的操作。
> 在 RBAC 中，用户被授予角色，而角色被授予权限。这种授权模型具有以下优点：
> 简化了权限管理：可以将权限分配到角色中，而不必将权限分配给每个用户，从而大大简化了权限管理的复杂度。
> 提高了安全性：RBAC 的访问控制模型可以更好地控制用户对资源的访问，减少了对系统的潜在威胁，提高了安全性。
> 增加了灵活性：RBAC 允许管理员根据需要创建新角色或修改现有角色，从而增加了系统的灵活性。
> 在 RBAC 中，每个角色代表了一组操作权限，而用户被授权访问这些操作权限。
> 系统将角色和用户设计为一对多关系，这样可以更加凸显角色的功能。您也可以很方便的修改为多对多。

系统采用了 [Spring Security](https://spring.io/projects/spring-security) + Jwt 实现的鉴权。
前端访问需携带Token，后端通过解析Token获取用户信息，进行权限验证。
```shell
请求头 ->  Authorization: Bearer token
```

### 拦截原理
程序在Gateway中进行验证此token并将验证成功的用户信息放入请求头中，传递给后端服务。
授权过滤类在 xyz.chener.zp.zpgateway.config.SecurityRepository 中。
```java
//Gateway是WebFlux的，所以这里要用 (代码108行)
Mono.fromFuture(CompletableFuture.supplyAsync(() -> {...})
        .flatMap(userBaseInfo -> {  return ... });
```
CompletableFuture中通过OpenFeign请求User模块获取用户信息鉴权。<br>

过滤链在 xyz.chener.zp.zpgateway.config.SecurityConfig 中进行注册 (代码 47行)
```java
    @Bean
    @RefreshScope  // 配合Nacos刷新白名单
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http)
    {
        http.authorizeExchange(exchangeSpec -> {
                    ServerHttpSecurity.AuthorizeExchangeSpec e = exchangeSpec;
                    ArrayList<String> list = new ArrayList<>();
                    list.addAll(commonConfig.getSecurity().getWriteList());
                    WriteListListener.writeListMap.values().forEach(list::addAll);
                    for (String s : list) {
                        e = e.pathMatchers(s).permitAll();
                    }
                    e.anyExchange().access(new AuthorizationManager());
        }).httpBasic().disable()
                .formLogin().disable()
                .logout().disable()
                .anonymous().disable()
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .and()
                 // 这里添加过滤器
                .addFilterBefore(new SecurityRepository(userModuleService,jwt,commonConfig), SecurityWebFiltersOrder.AUTHENTICATION)
                .csrf().disable()
                .cors();
        return http.build();
    }
```

网关中也实现了简单的IP拦截功能，通过Nacos动态配置，可以实现IP黑白名单功能。核心代码在
xyz.chener.zp.zpgateway.config.GatewayIpConfig 中实现。
```java
    @Bean
    // 这个是Spring Gateway的过滤器，不是Spring Security的，注意顺序
    @Order(Ordered.LOWEST_PRECEDENCE-99)
    public GlobalFilter ipFilter()
    {
        return (exchange, chain) -> {
            if (gatewayCostomProperties.getIp().getEnable() ) {
                // 省略......
            }
            return chain.filter(exchange);
        };
    }

```

在其它服务模块中，通过引入common组件实现鉴权。<br>
common组件通过starter自动配置机制将 xyz.chener.zp.common.config.security.SecurityConfig 注册到Spring容器中。
```java
    // 实现流程 (代码 57行)
    @Bean
    @RefreshScope
    @Primary
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 白名单自动配置
        ArrayList<String> urls = new ArrayList<>();
        urls.addAll(commonConfig.getSecurity().getWriteList());
        urls.addAll(WriteListAutoConfig.writeList);
        String[] writeList = urls.toArray(new String[0]);
        // 配置过滤器
        http.formLogin().disable()
        .logout().disable()
        ........
        ........
        .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
        .cors().and()
        .csrf().disable();
        return http.build();
    }
```
过滤器代码就不做展示了，大致功能就是根据请求头的信息来给当前请求设置用户信息，
可以在common组件中 xyz.chener.zp.common.config.security.AuthFilter 查看。<br>
<br>
<br>
### 白名单动态注册原理

首先看common组件中 xyz.chener.zp.common.config.writeList.WriteListAutoConfig
```java
@Configuration
public class WriteListAutoConfig implements EnvironmentAware, BeanDefinitionRegistryPostProcessor {

    private String contextPath = null;

    public static List<String> writeList = Collections.EMPTY_LIST;

    @Override
    public void setEnvironment(Environment environment) {
        contextPath = environment.getProperty("server.context-path");
    }

    public void setWriteList(List<Class<?>> classes) {
        ArrayList<String> write = new ArrayList<>();
        // 省略......
        writeList = Collections.unmodifiableList(write);
    }

    private String[] getMethodRestPath(Method method,Class<?> clazz){
        // 通过反射获取方法和类的注解，比如GetMapping、PostMapping等
        // 构建URI返回
        // 省略......
    }

    private String[] getPaths(String parentPath, String[] values) {
        // 省略......
    }

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
        // 这里是Spring的BeanDefinitionRegistryPostProcessor的方法
        // 可以获取到注册到Spring上下文的所有Bean定义
        // 通过Bean定义可以拿到类的信息，通过查看有没有白名单注解来实现注册
        // 省略......
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {

    }
}
```
这个类的作用就是通过Spring提供的机制，将含有某注解的方法添加到 writeList
这个静态变量中。<br>
然后通过 xyz.chener.zp.common.config.writeList.WriteListRegister
注册到Nacos中，代码很简单就不贴了，Bean定义注册阶段是要先于Bean实例化的，
所以不用担心还没有查找完整就提交到Nacos中。<br>
<br>
网关中通过 xyz.chener.zp.zpgateway.config.WriteListListener
监听Nacos中的实例，当实例变化时，获取到实例的信息并保存到一个线程安全的List中，
并且发布上下文刷新事件，动态刷新上方提到的 SecurityWebFilterChain 中的白名单配置。
> 注意这里有一个坑，因为这个类执行时机是在Application上下文
> 初始化后执行的，这时 RefreshEventListener 还没有初始化完成
> 如果这是发布refresh事件将无法通知Bean动态刷新，所以需要等待
> RefreshEventListener 初始化完成后再发布事件。
代码如下: (119行)
```java
private void waitRefreshListenerRunning(){
// 暂时解决 refresh 事件在 RefreshEventListener 未初始化完成时就发布的问题
CompletableFuture.runAsync(()->{
        try {
            RefreshEventListener rel = applicationContext.getBean(RefreshEventListener.class);
            if (rel != null)
            {
                Field ready = RefreshEventListener.class.getDeclaredField("ready");
                boolean ac = ready.canAccess(rel);
                ready.setAccessible(true);
                AtomicBoolean o = (AtomicBoolean) ready.get(rel);
                ready.setAccessible(ac);
                int i = 0;
                while (!o.get() && i++ < 100)
                {
                    Thread.sleep(500);
                }
                if (isFirstRefresh.compareAndSet(true,false)) {
                    applicationContext.publishEvent(new RefreshEvent(this, null, "writeList Refresh Event"));
                }
            }
        }catch (Exception ignored) {
            isFirstRefresh.set(false);
        }
    });
}
```

这样就实现了通过 @WriteList 注解动态注册白名单的功能。<br>
并且可以通过 @PreAuthorize 按照权限拦截。<br>



## 统一返回和异常处理

### 返回
在common组件中，通过starter自动配置机制将
xyz.chener.zp.common.config.unifiedReturn.UnifiedReturnConfig
注册到Spring容器中。 <br><br>
这个类继承了 ApplicationListener(ApplicationStartedEvent)
在Spring容器启动后，找到 RequestMappingHandlerAdapter 这个Bean，
这个Bean可以通过 setReturnValueHandlers(List) 方法设置返回值处理器，
将自己的统一返回处理添器添加到List头部。<br><br>
返回处理器实现大致如下:

```java
public class UnifiedReturnHandle  implements HandlerMethodReturnValueHandler {
    @Override
    public boolean supportsReturnType(MethodParameter returnType) {
        // 省略 ......
        // 判断是否含有需要统一返回的注解
    }


    @Override
    public void handleReturnValue(Object returnValue, MethodParameter returnType, ModelAndViewContainer mavContainer, NativeWebRequest webRequest) throws Exception {
        // 省略 ......
        // 有注解的话会执行这里
        // 大致逻辑就是 判断是否为 xyz.chener.zp.common.entity.R 类型
        // 如果是的话直接返回，如果不是的话，包装成 R 类型返回
        // 使用Jackson进行序列化，在 Jackson 中加入了自定义序列化器，为后续加密、脱敏等准备
    }
}
```

### 异常处理

在common组件中，通过starter自动配置机制将
xyz.chener.zp.common.config.unifiedReturn.UnifiedErrorReturn
注入容器，这个类含有 @RestControllerAdvice 注解。 <br>
这个类的作用就是处理全局异常，通过 @ExceptionHandler 注解来处理具体的异常。<br>
因为它不能通过多个 @ExceptionHandler 注解来处理单独的和默认的异常，意思就是
如果我拦截了Exception后，其它异常也会直接走到这里，所以需要自己实现一个错误分发器。<br>
具体代码如下:
```java
    @ExceptionHandler(Exception.class)
    public R<String> exceptionDispatch(Exception exception, HttpServletRequest request, HttpServletResponse response)
    {
        AtomicReference<R<String>> res = new AtomicReference<>(null);
        Arrays.stream(this.getClass().getDeclaredMethods()).filter(method -> {
            DispatchException de = method.getAnnotation(DispatchException.class);
            if (Objects.nonNull(de))
            {
                for (Class<? extends Throwable> aClass : de.value()) {
                    if (aClass.isAssignableFrom(exception.getClass()))
                        return true;
                }
            }
            return false;
        }).forEach(m->{
            boolean b = m.canAccess(this);
            m.setAccessible(true);
            try {
                Class<?>[] otherParams = m.getAnnotation(DispatchException.class).otherParams();
                ArrayList<Object> args = new ArrayList<>();
                args.add(exception);
                for (Class<?> param : otherParams) {
                    if (param.isAssignableFrom(HttpServletRequest.class))
                        args.add(request);
                    else if (param.isAssignableFrom(HttpServletResponse.class))
                        args.add(response);
                    else if (param.isAssignableFrom(HttpSession.class))
                        args.add(request.getSession());
                    else if (param.isAssignableFrom(ServletContext.class))
                        args.add(request.getServletContext());
                    else args.add(null);
                }
                res.set((R<String>) m.invoke(this, args.toArray()));
            } catch (Exception ignored) { }
            finally {
                m.setAccessible(b);
            }
        });

        if (Objects.isNull(res.get()))
        {
            LoggerUtils.logErrorStackTrace( exception,log);
            return R.Builder.<String>getInstance()
                    .setCode(R.HttpCode.HTTP_ERR.get())
                    .setMessage(String.format("%s [%s]"
                            ,R.ErrorMessage.HTTP_ERR.get()
                            ,exception.getClass().getSimpleName()))
                    .build();
        }
        return res.get();
    }
```

这里通过自定义注解 @DispatchException 来标记各个异常处理的方法，如果没有找到对应的异常处理方法，
将走默认处理。 <br>
例如我想自定义处理 AccessDeniedException :
```java
    // 注解中通过 value 来指定要处理的异常，通过 otherParams 来指定额外的参数
    @DispatchException(value = AccessDeniedException.class,otherParams = {HttpServletRequest.class,HttpServletResponse.class})
    public R<String> accessDeniedException(AccessDeniedException exception, HttpServletRequest request, HttpServletResponse response)
    {
        try {
            AccessDeniedProcess accessDeniedProcess = ApplicationContextHolder
                    .getApplicationContext()
                    .getBean(AccessDeniedProcess.class);
            // 处理的方法
            accessDeniedProcess.handle(request,response,exception);
        } catch (Exception e) { }
        return new R<>();
    }
```
> 这里是可以直接返回 R 对象，也可以直接通过 Response 直接输出。


## 自定义查询
> 通过前端传参来控制Select查询的字段，这样可以减少不必要的数据传输，提高效率。

因为在每个查询的时候如果都通过 MyBatis Plus 来控制查询的字段，会导致每个查询都要写，
所以这里通过 MyBatis 的拦截器来实现。<br>
先从使用上看:
```java
    @GetMapping("/getRoleList")
    @PreAuthorize("hasAnyRole('microservice_call','user_permission_list')")
    public PageInfo<Role> getRoleList(@ModelAttribute Role role
            , @ModelAttribute FieldQuery query
            , @RequestParam(defaultValue = "1") Integer page
            , @RequestParam(defaultValue = "10") Integer size)
    {
        PageHelper.startPage(page,size);
        QueryHelper.StartQuery(query,Role.class);
        return new PageInfo<>(roleService.lambdaQuery(role).list());
    }
```
这里通过 FieldQuery 来接收前端传来的查询字段，然后通过 QueryHelper.StartQuery 来启动查询功能。
<br>
```java
    public static CustomFieldQueryCloseable StartQuery(FieldQuery query, Class<?> entityClass){
        List<String> cols = query.getQueryFields();
        if (cols == null || cols.size() == 0)
            return new CustomFieldQueryCloseable();
        AssertUrils.state(!entityClass.equals(FieldQuery.class),new CostomFieldQueryError("StartQuery entity class cannot be its own"));

        ChainParam param = new ChainParam();
        param.queryFields = cols;
        param.entityClass = entityClass;
        List<TableField> tableAndFields = null;
        try {
            ResultWrapper resultWrapper = (ResultWrapper) ChainStarter.startTree(new MbpNormalChange(), param);
            tableAndFields = resultWrapper.result();
        } catch (Exception ignored) { }
        if (tableAndFields != null) {
            localVar.set(tableAndFields);
        }
        return new CustomFieldQueryCloseable();
    }
```

这里通过 ChainStarter.startTree(new MbpNormalChange(), param);
来启动一个链式调用 (ChainStarter的实现原理后面会提到)。<br>
大致流程为: <br>
* 通过 MbpNormalChange 来获取实体类是MybatisPlus的还是普通的实体类
* 如果是Mbp的实体类，根据mbp的注解来获取表名，并将表名和查询的字段名包装成一个List
* 如果是普通的实体类，通过自定义注解获取每个字段对应的表名，并将表名和查询的字段名包装成一个List
* 如果有一些字段是后端必须要求前端拿到的，通过自定义注解，也会添加到List中
* 将这个List存入ThreadLocal中 。
* 在MyBatis拦截器中，通过查看ThreadLocal中是否有数据。如果有数据，将查询的表名以及别名，通过List中的数据信息，包装成Select语句执行。(这里用到了JSQLParser辅助我们解析SQL)
* 这时查到的数据就只包含前端想要的以及必须要的数据。

<br><br>
上述的 'List' 包装过程在 xyz.chener.zp.common.config.query.processor 这个包中 <br>
Mybatis拦截器实现在 xyz.chener.zp.common.config.query.CustomFieldsQueryInterceptor 中 <br>
拦截器注入在 xyz.chener.zp.common.config.query.MybatisInterceptorsConfig 中实现,这里也参考了PageHelper拦截器的注入过程。 <br>
> 注意: 这里的拦截器要在PageHelper拦截器之前执行，
> 因为PageHelper拦截器会将查询的SQL先进行COUNT，
> 这时会影响我们的自定义查询字段，但MyBatis调用链是逆序的，
> 所以需要将我们的拦截器放到最后才会最先执行。



## 参数解密
> 解决前端传参如果加密后传参，无需手动解密。

这里通过几个自定义注解，并自定义了 SpringMVC 的参数解析器来实现。<br>
注解对应关系为: <br>
* @ModelAttributeDecry --> @ModelAttribute <br>
* @RequestParamDecry --> @RequestParam <br>
* @RequestBodyDecry --> @RequestBody <br>

<br>
分别通过 xyz.chener.zp.common.config.paramDecryption.core.ModelAttributeDecryResolver、
xyz.chener.zp.common.config.paramDecryption.core.RequestParamDecryResolver、
xyz.chener.zp.common.config.paramDecryption.core.RequestBodyDecryResolver 来解析参数。<br>
具体实现原理也很简单，这里不再举例说明，想了解的可以参考代码。<br>

默认解密方式为Base64，如果需要自定义解密方式，可以通过实现 xyz.chener.zp.common.config.paramDecryption.decryProcess.DecryInterface 接口来实现。<br>

```java
@PostMapping("/userDoLogin")
@WriteList
public LoginResult userDoLogin(@RequestParamDecry(value = "username",decryClass = 您自定义的解密类) String username
        ,@RequestParamDecry(value = "phone",decryClass = 您自定义的解密类) String phone
        ,@RequestParamDecry(value = "email",decryClass = 您自定义的解密类) String email
        , @RequestParamDecry(value = "password",decryClass = 您自定义的解密类) String password, @RequestParam String verification);
```

注入方式参考统一返回的注入方式，取到 RequestMappingHandlerAdapter 这个Bean，
然后通过 setArgumentResolvers 方法来注入自定义的参数解析器。<br>



## 出参加密、脱敏、权限

这里通过在上述的[统一返回](/basics/gnmk/houduan.html#统一返回和异常处理)中，自定义Jackson序列化器实现的，是统一返回的一个扩展功能。<br>
添加序列化器方式如下(xyz.chener.zp.common.config.unifiedReturn.UnifiedReturnHandle:49行):
```java
    @Override
    public void handleReturnValue(Object returnValue, MethodParameter returnType, ModelAndViewContainer mavContainer, NativeWebRequest webRequest) throws Exception {
        省略......
        ObjectMapper om = new ObjectMapper();
        if ((returnType.hasMethodAnnotation(EncryResult.class)
                || returnType.getDeclaringClass().isAnnotationPresent(EncryResult.class))
                && returnValue != null){
                省略......
            }else {
                SimpleModule sm = new SimpleModule();
                sm.addSerializer(String.class, new EncryCore.EncryJacksonSerializerDispatch<>(String.class));
                Class[] allType = {String.class,Integer.class,Long.class
                        ,Double.class,Float.class,Boolean.class,Short.class
                        , BigDecimal.class, BigInteger.class,Date.class};
                for (Class type : allType) {
                    // 这里注入序列化器，基本类型都需要添加
                    sm.addSerializer(type, new EncryCore.EncryJacksonSerializerDispatch<>(type));
                }
                om.registerModule(sm);
            }
        }
        省略......
    }
```

主要处理逻辑在 xyz.chener.zp.common.config.unifiedReturn.encry.core.EncryCore.EncryJacksonSerializer <br>
通过注解 @EncryField 来判断是否处理以及当前用户是否具有权限。<br>
```java
// 主要逻辑
@Override
public void serialize(Object value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
    // 空直接返回
    if (value == null){
        gen.writeNull();
        return;
    }
    // 判断权限
    String[] authority = encryField.hasAnyAuthority();
    if (authority.length > 0 && !SecurityUtils.hasAnyAuthority(authority)){
        gen.writeString("权限不足,无法显示");
        return;
    }
    if (!encryField.enableEncry()){
        gen.writeString(covertToString(value));
        return;
    }
    EncryInterface instance = null;
    try {
        instance = (EncryInterface) encryField.encryClass().getConstructor().newInstance();
    } catch (Exception ingored) {
        log.warn("{} 实例化失败",encryField.encryClass().getName());
    }
    Object result = null;
    if (instance !=null){
        result = instance.encry(covertToString(value),encryField);
    }
    if (result == null){
        gen.writeNull();
    }else {
        gen.writeString(result.toString());
    }
}
```

## 操作日志记录

这里通过自定义注解 @OpLog 和切面来实现。<br>
主要实现类: xyz.chener.zp.common.config.opLog.aop.OpRecordAop <br>
通过继承接口来指定记录的实现方式，默认为StdOut。
```java
public interface OpRecordInterface {
    void record(String opName,String paramJson,String resultJson
            ,Boolean isThrowException,Throwable throwable);
}
```
例如user模块中的实现 xyz.chener.zp.zpusermodule.config.oplog.OpRecordMybatisWrapper <br>
<br>
<br>

## 声明式HTTP客户端

::: tip
这里http客户端选用OKHttp3，虽然Spring6已经自带了声明式HTTP客户端，但它
是基于Reactor的，需要引入额外的包，并且自定义配置也不够灵活，无法自定义DNS等，故选用OKHttp3进行重写。
:::
> 注解完全使用Spring中的注解进行声明，方便切换实现。
> 例如 @HttpExchange、@PostExchange、@RequestParam 等注解。

实现代码位于 xyz.chener.zp.common.config.okhttpclient 中，这里也参考了Mybatis Mapper的实现方式。<br>

这里扫描所有的类，将含有某注解的类转化为Bean定义，然后添加到Bean工厂中。注意，这里的Bean是一个代理类。<br>
```java
public class HttpRequestInterfaceInject implements BeanDefinitionRegistryPostProcessor {
    private AbstractBeanDefinition processBeanDefinition(Class clazz)
    {
        // 这里将类转化为Bean定义，并将需要的字段注入到Bean中
        // 省略......
        return bd;
    }
    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
        // 这里扫描所有的类，将含有某注解的类转化为Bean定义，然后添加到Bean工厂中
        // 详细处理方式可查看源码 xyz.chener.zp.common.config.okhttpclient.HttpRequestInterfaceInject#postProcessBeanDefinitionRegistry
        // 省略......
    }
    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {

    }
}
```

<br>


代理类的实现如下:
::: tip
可以从 invoke 方法中开始看，已省略和流程无关的代码
:::
```java
public class OkHttpInterfaceBeanFactory implements FactoryBean {
    private Class mapperInterface;

    private OkHttpClient http;

    public OkHttpClient getHttp() {
        return http;
    }

    public void setHttp(OkHttpClient http) {
        this.http = http;
    }

    public OkHttpInterfaceBeanFactory() {
    }

    public OkHttpInterfaceBeanFactory(Class mapperInterface) {
        this.mapperInterface = mapperInterface;
    }

    public Class getMapperInterface() {
        return mapperInterface;
    }

    public void setMapperInterface(Class mapperInterface) {
        this.mapperInterface = mapperInterface;
    }

    @Slf4j
    private static class RequestJdkProxy implements InvocationHandler, Serializable{

        private static final String GET = "GET";
        private static final String POST = "POST";

        @Data
        private static class RequestMetaData{
            private String url;
            private String method;
            private Map<String,Object> params;
            private String jsonParams;
            private Map<String,String> headers;
            private Map<String,String> pathParams;
        }

        private OkHttpClient client;


        public RequestJdkProxy(OkHttpClient client) {
            this.client = client;
        }

        private RequestMetaData getMethodMetaData(Method method,Object proxyObj,Object[] args){
            // 包装请求元数据
            RequestMetaData md = new RequestMetaData();
            md.setUrl(getUrl(method));
            GetExchange getAnn = method.getAnnotation(GetExchange.class);
            PostExchange postAnn = method.getAnnotation(PostExchange.class);
            AssertUrils.state(getAnn != null || postAnn != null, OkHttpInterfaceRequestMethodError.class);
            Map<String, String> headers = getHeaders(method, proxyObj,args);
            Map<String, Object> params = getFormDataParams(method, proxyObj, args);
            String jsonParams = getJsonParams(method, proxyObj, args);
            Map<String, String> pathParam = getPathParam(method, proxyObj, args);
            if (getAnn != null) {
                md.setMethod(GET);
            }else {
                md.setMethod(POST);
            }
            md.setHeaders(headers);
            md.setPathParams(pathParam);
            md.setParams(params);
            md.setJsonParams(jsonParams);
            return md;
        }

        private Map<String,String> getHeaders(Method method,Object obj,Object[] args){
            // 构建请求头
        }

        private Map<String,String> getPathParam(Method method,Object obj,Object[] args){
            // 构建路径参数
        }

        private String safeGetObjectString(Object obj){
            // ... 
        }

        private Map<String,Object> getFormDataParams(Method method, Object obj, Object[] args){
            // 构建POST表单请求 ... 
        }

        private void getFormDataParamsForObject(Map<String, Object> sourceMap,Object obj,Class objClazz){
            // POST请求，表单类型并且是对象，处理并存入sourceMap
        }
        private Boolean addFormDataParam(Map<String, Object> sourceMap,Object obj,String key){
            // POST请求，如果是表单类型，并且是基本类型，构建表单参数，存入sourceMap
        }

        private String getJsonParams(Method method, Object obj, Object[] args){
            // POST请求，并且有@RequestBody注解，则将参数转换为JSON字符串
        }


        private String getUrl(Method method){
            // 构建请求URL
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            // 主要请求逻辑 
            // 包装请求元数据
            RequestMetaData methodMetaData = getMethodMetaData(method, proxy, args);
            processPathParam(methodMetaData);
            Request request;
            ObjectMapper om = new ObjectMapper();
            // get 和 post 进行不同的处理
            if (methodMetaData.getMethod().equalsIgnoreCase(GET)){
                request = processGetRequest(methodMetaData);
            }else if(methodMetaData.getMethod().equalsIgnoreCase(POST)){
                request = processPostRequest(methodMetaData);
            }else {
                throw new OkHttpInterfaceRequestMethodError();
            }
            Response resp = client.newCall(request).execute();
            // 根据返回类型进行处理
            if (method.getReturnType().isAssignableFrom(ResponseBody.class)) {
                return resp.body();
            }
            try (resp){
                String bodyStr = resp.body().string();
                if (!resp.isSuccessful()) {
                    OkHttpResponseError err = new OkHttpResponseError();
                    err.setBodyStr(bodyStr);
                    err.setHttpCode(resp.code());
                    err.setHttpErrorMessage(resp.message());
                    throw err;
                }
                om.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
                return getResponseToReturnType(method, om, bodyStr);
            }
        }

        @Nullable
        private Object getResponseToReturnType(Method method, ObjectMapper om, String bodyStr) throws JsonProcessingException {
            // 按照不同的返回类型进行处理适配
        }

        @NotNull
        private Request processPostRequest(RequestMetaData methodMetaData)  {
            // 包装一个POST请求 ，具体代码省略
            return request;
        }

        @NotNull
        private Request processGetRequest(RequestMetaData methodMetaData) {
            // 包装一个GET请求 ，具体代码省略
            return request;
        }

        private void processPathParam(RequestMetaData methodMetaData) {
            // 处理路径参数，具体代码省略
        }
    }

    @Override
    public Object getObject() throws Exception {
        return Proxy.newProxyInstance(this.getClass().getClassLoader()
                , new Class[]{mapperInterface}, new RequestJdkProxy(http));
    }

    @Override
    public Class<?> getObjectType() {
        return mapperInterface;
    }

    @Override
    public boolean isSingleton() {
        return FactoryBean.super.isSingleton();
    }
}
```

<br>

并且这里通过定义 HttpRequestContextHolder 来实现简单的请求上下文，方便临时修改请求的实际地址等信息，当然你也可以扩展更多信息 :satisfied: <br>
具体可查看 xyz.chener.zp.common.config.okhttpclient.HttpRequestContextHolder 。<br>

## 指定负载均衡

### 负载均衡

::: tip
这里通过自定义负载均衡策略来达到指定调用某服务
:::
主要代码在 xyz.chener.zp.common.config.feign.loadbalance 包下 <br>
负载均衡策略参考 org.springframework.cloud.loadbalancer.core.RoundRobinLoadBalancer ，并在其基础上改动。
```java
public class NormalLoadBalance implements ReactorServiceInstanceLoadBalancer {

    private static final Logger log = LoggerFactory.getLogger(NormalLoadBalance.class);

    final AtomicInteger position;

    final String serviceId;

    ObjectProvider<ServiceInstanceListSupplier> serviceInstanceListSupplierProvider;


    public NormalLoadBalance(ObjectProvider<ServiceInstanceListSupplier> serviceInstanceListSupplierProvider,
                                  String serviceId) {
        this(serviceInstanceListSupplierProvider, serviceId, new Random().nextInt(1000));
    }


    public NormalLoadBalance(ObjectProvider<ServiceInstanceListSupplier> serviceInstanceListSupplierProvider,
                                  String serviceId, int seedPosition) {
        this.serviceId = serviceId;
        this.serviceInstanceListSupplierProvider = serviceInstanceListSupplierProvider;
        this.position = new AtomicInteger(seedPosition);
    }

    @SuppressWarnings("rawtypes")
    @Override
    public Mono<Response<ServiceInstance>> choose(Request request) {
        ServiceInstanceListSupplier supplier = serviceInstanceListSupplierProvider
                .getIfAvailable(NoopServiceInstanceListSupplier::new);
        // 这里通过ThreadLocal获取指定的服务地址
        ServerInstance nextInstance = LoadbalancerContextHolder.getNextInstance();
        return supplier.get(request).next()
                .map(serviceInstances -> processInstanceResponse(supplier, serviceInstances,nextInstance));
    };

    private Response<ServiceInstance> processInstanceResponse(ServiceInstanceListSupplier supplier,
                                                              List<ServiceInstance> serviceInstances,
                                                              ServerInstance nextInstance) {
        Response<ServiceInstance> serviceInstanceResponse = getInstanceResponse(serviceInstances,nextInstance);
        if (supplier instanceof SelectedInstanceCallback && serviceInstanceResponse.hasServer()) {
            ((SelectedInstanceCallback) supplier).selectedServiceInstance(serviceInstanceResponse.getServer());
        }
        return serviceInstanceResponse;
    }

    private Response<ServiceInstance> getInstanceResponse(List<ServiceInstance> instances,ServerInstance nextInstance) {
        if (instances.isEmpty() && nextInstance == null) {
            if (log.isWarnEnabled()) {
                log.warn("No servers available for service: " + serviceId);
            }
            return new EmptyResponse();
        }

        if (nextInstance != null){
            for (ServiceInstance instance : instances) {
                // 如果能找到指定的实例，则返回该实例
                if (instance.getHost().equals(nextInstance.host()) && instance.getPort() == nextInstance.port()){
                    return new DefaultResponse(instance);
                }
            }
            log.warn("自定义IP负载均衡:未找到指定的实例[{}:{}],将返回空实例", nextInstance.host(), nextInstance.port());
            return new EmptyResponse();
        }

        if (instances.size() == 1) {
            return new DefaultResponse(instances.get(0));
        }

        int pos = this.position.incrementAndGet() & Integer.MAX_VALUE;

        ServiceInstance instance = instances.get(pos % instances.size());

        return new DefaultResponse(instance);
    }
}
```

> 通过 LoadbalancerContextHolder 可轻松控制OpenFeign下一次调用的实例 <br>
> 具体的实例地址如何取到，在后续的 [Utils说明](/xmxj/gmmk/hdxj.html#各utils类说明) 中会有说明。

::: warning
如何启用？
:::
启用需在启动类上标注 LoadBalancerClients 注解，并指定哪个服务启用，如下：
```java
// 例如
@LoadBalancerClients({
        @LoadBalancerClient(name = "zp-user-module",configuration = NormalLoadBalanceAutoConfiguration.class)
})
```

此服务名对应OpenFeign接口中的服务名，如下：
```java
@FeignClient(name = "zp-user-module",fallback = UserModuleServiceFallback.class)
public interface UserModuleService {
    @RequestMapping(value = "/api/web/getWsOnlineUsersForMs",method = RequestMethod.GET)
    List<String> getWsOnlineUsersName();
}
```

### OpenFeign扩展

#### OpenFeign 自定义请求头
```java
public class FeignRequestInterceptor  implements RequestInterceptor {
    private final CommonConfig commonConfig;

    public FeignRequestInterceptor(CommonConfig commonConfig) {
        this.commonConfig = commonConfig;
    }

    @Override
    public void apply(RequestTemplate template) {
        // 这里添加自定义请求头
        // 这里添加了一个自定义请求头，用于标识该请求是通过OpenFeign发起的，如果权限中配置了允许
        // 部分权限调用，也会根据该请求头来判断是否允许调用
        template.header(CommonVar.OPEN_FEIGN_HEADER, commonConfig.getSecurity().getFeignCallSlat());
    }
}
```
#### OpenFeign 返回自动值处理
```java
@Slf4j
public class FeignResultDecoder implements Decoder {
    @Override
    public Object decode(Response response, Type type) throws IOException, DecodeException, FeignException {
        // 这里的逻辑为:
        // 如果是需要R对象，则直接返回R对象
        // 如果是需要其它对象，则返回R对象中的obj字段
        // 这里使用了 TypeFactory 来使用字符串拼接泛型供Jackson解析
        try {
            String body = new String(response.body().asInputStream().readAllBytes(), StandardCharsets.UTF_8);
            ObjectMapper om = new ObjectMapper();
            om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            R<?> obj = om.readValue(body, TypeFactory.defaultInstance()
                    .constructFromCanonical(String.format("%s<%s>", R.class.getName(), type.getTypeName())));
            if (obj.getCode()!=R.HttpCode.HTTP_OK.get())
            {
                log.warn("openfeign call error : "+obj.getMessage());
            }
            return obj.getObj();
        }catch (Exception exception)
        {
            exception.printStackTrace();
            log.error(exception.getMessage());
            throw new RuntimeException(R.ErrorMessage.FEIGN_DECODER_ERROR.get());
        }
    }
}
```

::: tip
注入直接新增 Decoder 和 FeignRequestInterceptor 的Bean即可。
:::


## 动态验参
> 这里实现了通过注解来校验部分参数的MD5值，防止参数被篡改。 <br>
> 参数其它校验引入 validation 即可。

主要流程为:
* 通过注解启用，并标明MD5值在哪个字段
* 判断多种参数类型，获取参数值
* 计算并检验

```java
public class DynamicVerAop {
    
    // ...... 省略部分代码
    
    @Pointcut("@annotation(xyz.chener.zp.common.config.dynamicVerification.annotation.Ds)" +
            " && (@annotation(org.springframework.web.bind.annotation.GetMapping) " +
            "|| @annotation(org.springframework.web.bind.annotation.PostMapping) " +
            "|| @annotation(org.springframework.web.bind.annotation.PutMapping) " +
            "|| @annotation(org.springframework.web.bind.annotation.DeleteMapping) " +
            "|| @annotation(org.springframework.web.bind.annotation.RequestMapping))")
    public void dsPointcut() { }


    // 主要逻辑 
    @Around("dsPointcut()")
    public Object dsAround(ProceedingJoinPoint pjp) throws Throwable {
        try {
            Signature signature = pjp.getSignature();
            if (signature instanceof MethodSignature methodSignature)
            {
                Method targetMethod = methodSignature.getMethod();
                Ds dsAnn = targetMethod.getAnnotation(Ds.class);
                String dsValueFieldName = dsAnn.value();
                Class<?> dsClazz = dsAnn.verImplClass();
                // 获取传来的MD5在哪个字段
                if (StringUtils.hasText(dsValueFieldName))
                {
                    // 获取参数元数据 (就是参数名 参数值 注解等)
                    Set<DsFieldsMetadata> metadataSet = getMethodDsFieldsMetadata(targetMethod);
                    // 获取校验实现类
                    DynamicVerRuleInterface dsInstance = getDsInstance(dsClazz);
                    ArrayList<String> args = new ArrayList<>();
                    // 遍历参数元数据，获取参数值存入args
                    // 不同类型(例如Map Collections等) 将有不同的处理方式
                    // 省略部分代码 .......
    
                    String[] argsArr = args.toArray(new String[0]);
                    // 调用校验实现类的verify方法，校验MD5
                    AssertUrils.state(ObjectUtils.nullSafeEquals(dsInstance.verify((Object[]) argsArr),dsValue),new RuntimeException("MD5 verification failed"));
                }
            }
        }catch (Exception e){
            log.error(e.getMessage());
            throw new DynamicVerificationError();
        }
        return pjp.proceed();
    }

    private void processObjectType(Object obj,DsFieldsMetadata metadata,List<String> resList){
        processObjectType(obj,metadata,resList,false);
    }
    private void processObjectType(Object obj,DsFieldsMetadata metadata,List<String> resList,Boolean isObjectRecurrence)
    {
        // 处理对象 将对象中的字段值拼接成字符串，Map和Obejct以及基本数据类型 有不同的处理方式
        // 省略部分代码 .......
    }

    private Object getFieldObject(Field field,Object obj){
        // 反射获取对象字段
    }

    private Object getObjectWithMultistageKey(Object map,String key){
        // 通过多级Key获取对象 eg: getObjectWithMultistageKey(map,"a.b.c")
    }

    private Object getObjectWithKey(Object map,String key){
        // 通过Key获取对象
    }

    private String processBaseType(Object obj){
        // 基本数据类型转为String
    }
    

    private DynamicVerRuleInterface getDsInstance(Class<?> clazz) throws NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        // 获取校验实现类
    }


    private Set<DsFieldsMetadata> getMethodDsFieldsMetadata(Method method) {
        // 获取参数元数据
    }

    private Annotation findAnnotation(Annotation[] annotations, Class<?> annotationClass) {
        for (Annotation a : annotations) {
            if (a.annotationType().getName().equals(annotationClass.getName())) {
                return a;
            }
        }
        return null;
    }

    private String[] getMethodParamName(Method method)
    {
        // 获取方法参数名称 这里借用了Spring的 DefaultParameterNameDiscoverer 类
        // 如果构建时有参数 -parameters 则可以直接获取到参数名称
        // 否则通过 asm 读取 class 文件获取参数名称
    }

    // 参数元数据实体类
    public static class DsFieldsMetadata implements Comparable<DsFieldsMetadata> {
        public Class<?> fieldClass;

        public Annotation fieldAnnotation;

        public String fieldName;

        public int order;

        public String[] dsObjectFieldNames;

        public int argIndex;

        @Override
        public boolean equals(Object obj) {
            if (obj == null) return false;
            if (obj instanceof DsFieldsMetadata dsFieldsMetadata) {
                return this.fieldName.equals(dsFieldsMetadata.fieldName);
            }
            return false;
        }

        @Override
        public int compareTo(DsFieldsMetadata o) {
            return this.order - o.order == 0 ? 1 : this.order - o.order;
        }
    }

}

```

## 接口防抖
> 这里实现了通过AOP来实现防抖，防止接口被同一参数频繁调用。 <br>

实现代码位于 xyz.chener.zp.common.config.antiShaking.aop.AntiShakingAop 类中。<br>
流程简单，具体流程可查阅代码。默认实现为Redis实现，可自行实现 AntiShakingInterface 接口，替换为Guava等。

::: warning
主要防止重复提交，这里不可当做限流使用。
:::

## 接口限流
::: tip
这里借助Sentinel实现接口限流，Sentinel资源和URL为一一对应关系，无法做到类似通配符匹配限流方法。<br>
这里扩展了一点功能，达到一个限流方式匹配多个URL的效果。<br>
:::

这里构造了 xyz.chener.zp.sentinelAdapter.currentlimit.CurrentLimitManager 类，用于管理限流资源。<br>
主要思路为: 接管Sentinel的FlowRuleManager，在 SphU.entry 获取资源的时候，返回资源名+UID的形式，<br>
这样既可以使同一个限流类型通配不同的URL或者方法，也可以完全不修改Sentinel原有的使用方式。<br>
```java
public class CurrentLimitManager {
    //  key:resource+uuid
    public static final ConcurrentHashMap<String, CurrentLimitRuleInfo> cache = new ConcurrentHashMap<>();
    //  key:resource
    public static final ConcurrentHashMap<String, FlowRule> rules = new ConcurrentHashMap<>();
    
    // 这里加载一个规则 参数:规则名和规则类
    public static void addRules(String resource,FlowRule rule){
        rules.put(resource,rule);
    }
    // 移除
    public static void removeRules(String resource){
        rules.remove(resource);
        ArrayList<String> removeKeys = new ArrayList<>();
        cache.forEach((key, value) -> {
            if (value.getResource().equals(resource)) {
                removeKeys.add(key);
            }
        });
        removeKeys.forEach(key -> {
            removeRule(key);
            cache.remove(key);
        });
    }
    
    // 验证缓存的规则是否有效 如果无效则移除
    public static void verifyAllRules(){
        ArrayList<String> removeKeys = new ArrayList<>();
        cache.forEach((key, value) -> {
            if (!rules.containsKey(value.getResource())) {
                removeKeys.add(key);
            }
        });
        removeKeys.forEach(key -> {
            removeRule(key);
            cache.remove(key);
        });
    }
    
    // 获取 SphU.entry 需要的资源名  传入规则名和UID 这个uid可以是url 也可以是方法全路径
    public static String getRulesName(String resource,String uuid){
        Objects.requireNonNull(resource);
        Objects.requireNonNull(uuid);
        if (cache.containsKey(resource+uuid)) {
            return cache.get(resource+uuid).getKey();
        }
        if (rules.containsKey(resource)) {
            FlowRule flowRule = rules.get(resource);
            flowRule.setResource(resource + uuid);
            loadRule(flowRule);
            CurrentLimitRuleInfo currentLimitRuleInfo = new CurrentLimitRuleInfo();
            currentLimitRuleInfo.setKey(resource + uuid);
            currentLimitRuleInfo.setResource(resource);
            cache.put(resource + uuid, currentLimitRuleInfo);
            return resource + uuid;
        }
        return null;
    }

    // 加载Sentinel限流规则
    private static synchronized void loadRule(FlowRule flowRule){
        ArrayList<FlowRule> flowRules = new ArrayList<>(FlowRuleManager.getRules());
        flowRules.add(flowRule);
        FlowRuleManager.loadRules(flowRules);
    }
    
    // 移除Sentinel限流规则
    private static synchronized void removeRule(String resource){
        ArrayList<FlowRule> flowRules = new ArrayList<>(FlowRuleManager.getRules());
        flowRules.removeIf(flowRule -> flowRule.getResource().equals(resource));
        FlowRuleManager.loadRules(flowRules);
    }

}
```

<br>
通过AOP来对接口或方法进行限流，实现类 xyz.chener.zp.sentinelAdapter.aop.CurrentLimitAop。<br>

限流规则配置可以通过代码配置也可以通过Nacos动态配置 <br>
下面是监听Nacos配置变化的方法，监听了限流和熔断降级配置。
```java
// xyz.chener.zp.sentinelAdapter.nacosclient.SentinelConfigChangeListener
@EnableConfigurationProperties(SentinelCustomConfig.class)
public class SentinelConfigChangeListener implements ApplicationListener<ApplicationStartedEvent> {

    private static Logger logger = org.slf4j.LoggerFactory.getLogger(SentinelConfigChangeListener.class);

    private final SentinelCustomConfig sentinelCustomConfig;

    public static final List<Consumer<List<FlowRule>>> flowChangeListeners = new CopyOnWriteArrayList<>();
    public static final List<Consumer<List<DegradeRule>>> degradeChangeListeners = new CopyOnWriteArrayList<>();

    private final ExecutorService pool = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(1), new NamedThreadFactory("sentinel-nacos-ds-update", true),
            new ThreadPoolExecutor.DiscardOldestPolicy());

    public SentinelConfigChangeListener(SentinelCustomConfig sentinelCustomConfig) {
        this.sentinelCustomConfig = sentinelCustomConfig;
    }

    @Override
    public void onApplicationEvent(ApplicationStartedEvent event) {
        // 这里添加了几个监听器，具体监听什么文件配置与yml中，配置文件类型参考Sentinel原来的类型
        if (sentinelCustomConfig.getEnableAutoLoad()){
            try {
                Properties nacosProperties = sentinelCustomConfig.covertToProperties();
                ConfigService configService = NacosFactory.createConfigService(nacosProperties);
                sentinelCustomConfig.getNacos().values().forEach(e->{
                    try {
                        if (e.getRuleType().equals("flow")) {
                            String config = configService.getConfig(e.getDataId(), sentinelCustomConfig.getGroupId(), 5000);
                            processFlowJson(config);
                            configService.addListener(e.getDataId(), sentinelCustomConfig.getGroupId(), new Listener() {
                                @Override
                                public Executor getExecutor() {
                                    return pool;
                                }

                                @Override
                                public void receiveConfigInfo(String configInfo) {
                                    processFlowJson(configInfo);
                                }
                            });
                        }
                        if (e.getRuleType().equals("degrade")) {
                            String config = configService.getConfig(e.getDataId(), sentinelCustomConfig.getGroupId(), 5000);
                            processDegradeJson(config);
                            configService.addListener(e.getDataId(), sentinelCustomConfig.getGroupId(), new Listener() {
                                @Override
                                public Executor getExecutor() {
                                    return pool;
                                }

                                @Override
                                public void receiveConfigInfo(String configInfo) {
                                    processDegradeJson(configInfo);
                                }
                            });
                        }
                    }catch (Exception exi){
                        throw new RuntimeException(exi);
                    }
                });
            }catch (Exception exception){
                logger.error("sentinel nacos config listener init error",exception);
            }
        }

    }

    private void processFlowJson(String configInfo) {
        // 处理nacos发来的限流json配置
    }

    private void processDegradeJson(String json){
        // 处理nacos发来的熔断降级json配置
    }

    private FlowRule parseFlowRule(Map map){
        // 通过Map获取限流规则
    }

    private DegradeRule parseDegradeRule(Map map){
        // 通过Map获取降级规则
    }

}


```

::: tip
暂未引入分布式限流,因为限流目的主要为了保护服务，并不是为了限制接口调用量，所以分布式限流的意义不大。<br>
如需实现，参考[Sentinel官方文档中的集群流量控制](https://sentinelguard.io/zh-cn/docs/cluster-flow-control.html)。
:::

## 熔断降级

这里AOP的实现方式参考上方 接口限流 的，基本一致。<br>
对于OpenFeign的支持实现，参考了 com.alibaba.cloud.sentinel.feign 包中的流程，重写了 SentinelInvocationHandler 。<br>

```java
@Override
public Object invoke(final Object proxy, final Method method, final Object[] args)
        throws Throwable {
    if ("equals".equals(method.getName())) {
        try {
            Object otherHandler = args.length > 0 && args[0] != null
                    ? Proxy.getInvocationHandler(args[0])
                    : null;
            return equals(otherHandler);
        }
        catch (IllegalArgumentException e) {
            return false;
        }
    }
    else if ("hashCode".equals(method.getName())) {
        return hashCode();
    }
    else if ("toString".equals(method.getName())) {
        return toString();
    }

    Object result;
    MethodHandler methodHandler = this.dispatch.get(method);
    // only handle by HardCodedTarget
    if (target instanceof Target.HardCodedTarget hardCodedTarget) {
        MethodMetadata methodMetadata = SentinelContractHolder.METADATA_MAP
                .get(hardCodedTarget.type().getName()
                        + Feign.configKey(hardCodedTarget.type(), method));
        // resource default is HttpMethod:protocol://url
        if (methodMetadata == null) {
            result = methodHandler.invoke(args);
        }
        else {
            // 这里重写了获取资源名的方法，达到上述功能
            String resourceName = methodMetadata.template().method().toUpperCase()
                    + ":" + hardCodedTarget.url() + methodMetadata.template().path();
            Entry entry = null;
            String prefix = "";
            try {
                CircuitBreakResourceFeign classResName = methodMetadata.targetType().getAnnotation(CircuitBreakResourceFeign.class);
                CircuitBreakResourceFeign methodResName = methodMetadata.method().getAnnotation(CircuitBreakResourceFeign.class);
                if (classResName != null && StringUtils.hasText(classResName.value())) {
                    prefix = classResName.value();
                }
                if (methodResName != null && StringUtils.hasText(methodResName.value())) {
                    prefix = methodResName.value();
                }
            }catch (Exception getNameException){
                System.err.println("自定义熔断资源名获取异常");
                throw getNameException;
            }
            if (StringUtils.hasText(prefix)) {
                resourceName = CircuitBreakRuleManager.getRulesName(prefix, resourceName);
            }

            try {
                ContextUtil.enter(resourceName);
                entry = SphU.entry(resourceName, EntryType.OUT, 1, args);
                result = methodHandler.invoke(args);
            }
            catch (Throwable ex) {
                // fallback handle
                if (!BlockException.isBlockException(ex)) {
                    Tracer.traceEntry(ex, entry);
                }
                if (fallbackFactory != null) {
                    try {
                        Object fallbackResult = fallbackMethodMap.get(method)
                                .invoke(fallbackFactory.create(ex), args);
                        return fallbackResult;
                    }
                    catch (IllegalAccessException e) {
                        // shouldn't happen as method is public due to being an
                        // interface
                        throw new AssertionError(e);
                    }
                    catch (InvocationTargetException e) {
                        throw new AssertionError(e.getCause());
                    }
                }
                else {
                    // throw exception if fallbackFactory is null
                    throw ex;
                }
            }
            finally {
                if (entry != null) {
                    entry.exit(1, args);
                }
                ContextUtil.exit();
            }
        }
    }
    else {
        // other target type using default strategy
        result = methodHandler.invoke(args);
    }

    return result;
}
```

::: tip
这里有个BUG，需要将配置文件 spring.cloud.openfeign.lazy-attributes-resolution 设置为true ，否则会报错。Spring Cloud Alibaba版本为2022.0.0.0-RC1。
后续官方会解决。[ISSUES](https://github.com/alibaba/spring-cloud-alibaba/issues/3024) <br>
:::

## 日志记录

这里通过对Logback的扩展，实现了对系统的日志记录入库。<br>
代码位于logger模块中，主要实现了自定义 Appender ，类 xyz.chener.zp.logger.logback.LogPushEsAppender 。<br>
按照ELK栈应该使用Logstash对日志进行处理推送，但由于资源有限，这里直接推送到了Elasticsearch中。<br>

大致逻辑:
* 在logback配置文件中拼接出json
* 在Appender中将json转换为实体类
* 交给推送线程处理

```xml
    <property name="JSON_LOG_PATTERN" value="
    {
        &quot;time&quot;:&quot;%d{yyyy-MM-dd HH:mm:ss.SSS}&quot;,
        &quot;tid&quot;:&quot;%tid&quot;,
        &quot;sId&quot;:&quot;%sId&quot;,
        &quot;iId&quot;:&quot;%iId&quot;,
        &quot;level&quot;:&quot;%level&quot;,
        &quot;thread&quot;:&quot;%t&quot;,
        &quot;logger&quot;:&quot;%logger&quot;,
        &quot;message&quot;:&quot;%msg&quot;
    }"/>
```

推送到Es中可搭配Kibana进行可视化展示，这里的日志推荐永久保存，Skywalking中链路日志一般只保留一段时间。<br>

## 系统信息
通过对Spring Boot Actuator，实现了对系统的信息收集。<br>

通过[Nacos API](https://nacos.io/zh-cn/docs/open-api.html)获取服务列表: 
```java
@HttpExchange(NacosRequest.NACOS_HOST)
public interface NacosRequest {
    String NACOS_HOST = " ";
    /**
     * 获取服务名列表
     * @param pageNo
     * @param pageSize
     * @param groupName
     * @param namespaceId
     * @return
     */
    @GetExchange("/nacos/v1/ns/service/list")
    ServerNames getServiceNameList(@RequestHeader("username") String username
            , @RequestHeader("password") String password
            ,@RequestParam("pageNo") int pageNo
            , @RequestParam("pageSize") int pageSize
            , @RequestParam("groupName") String groupName
            , @RequestParam("namespaceId") String namespaceId);
    /**
     * 按照服务名获取实例列表
     * @param serviceName
     * @param groupName
     * @param namespaceId
     * @return
     */
    @GetExchange("/nacos/v1/ns/instance/list")
    NacosServerInstance getInstanceList(@RequestHeader("username") String username
            , @RequestHeader("password") String password
            ,@RequestParam("serviceName") String serviceName
            , @RequestParam("groupName") String groupName
            , @RequestParam("namespaceId") String namespaceId);
    /**
     * 获取实例信息
     * @param serviceName
     * @param groupName
     * @param namespaceId
     * @param ip
     * @param port
     * @return
     */
    @GetExchange("/nacos/v1/ns/instance")
    ServerInstanceInfo getInstance(@RequestHeader("username") String username
            , @RequestHeader("password") String password
            , @RequestParam("serviceName") String serviceName
            , @RequestParam("groupName") String groupName
            , @RequestParam("namespaceId") String namespaceId
            , @RequestParam("ip") String ip
            , @RequestParam("port") int port);


}
```

Actuator信息收集 ([全部端点](https://docs.spring.io/spring-boot/docs/3.0.5/actuator-api/htmlsingle/)) : 
```java
@HttpExchange("http://none")
public interface ActuatorRequest {
    String prefix = "/actuator";

    @GetExchange(prefix+"/health")
    String getHealthBaseInfo(@RequestHeader(CommonVar.OPEN_FEIGN_HEADER) String headerKey);
    
    @GetExchange(prefix+"/metrics/{path}")
    String getMetrics(@RequestHeader(CommonVar.OPEN_FEIGN_HEADER) String headerKey
            , @PathVariable("path") String path);
    
    @GetExchange(prefix+"/sentinelCustom/{resourceName}")
    Map getSentinelCustom(@RequestHeader(CommonVar.OPEN_FEIGN_HEADER) String headerKey
            , @PathVariable("resourceName") String resourceName);
}
```


## 各Utils类说明

### common
#### AssertUrils
断言类，用于判断参数1是否成立，不成立则抛出异常。<br>
xyz.chener.zp.common.utils.AssertUrils#state(boolean, java.lang.Class<?>)<br>
xyz.chener.zp.common.utils.AssertUrils#state(boolean, java.lang.RuntimeException)

#### GZipUtils
json压缩为byte[] <br>
xyz.chener.zp.common.utils.GZipUtils#compressJson
byte[]解压为json <br>
xyz.chener.zp.common.utils.GZipUtils#uncompressJson

#### IpUtils
获取真实IP <br>
xyz.chener.zp.common.utils.IpUtils#getRealIp

#### Jwt
jwt工具类 <br>
xyz.chener.zp.common.utils.Jwt#encode(xyz.chener.zp.common.entity.LoginUserDetails)<br>
xyz.chener.zp.common.utils.Jwt#decode

#### LoggerUtils
日志工具类，打印异常堆栈及信息 <br>
xyz.chener.zp.common.utils.LoggerUtils#logErrorStackTrace

#### MapBuilder
Map构造器，用于构造Map <br>

#### Md5Utiles
获取数据的MD5值 <br>
xyz.chener.zp.common.utils.Md5Utiles#getDataMd5

#### NacosUtils
获取Nacos中的服务实例 <br>
xyz.chener.zp.common.utils.NacosUtils#getServerInstance

#### ObjectUtils
比较对象中部分字段是否相等<br>
xyz.chener.zp.common.utils.ObjectUtils#objectFieldsEquals <br>
获取方法引用的方法名 <br>
xyz.chener.zp.common.utils.ObjectUtils#getSFunctionName <br>
复制对象中的字段 <br>
xyz.chener.zp.common.utils.ObjectUtils#copyFields <br>
判断对象是否为基本类型 <br>
xyz.chener.zp.common.utils.ObjectUtils#isBasicType(java.lang.Object) <br>

#### RequestUtils
请求工具类，获取请求的实体，请求头等信息 <br>

#### SecurityUtils
权限工具类，判断是否有某权限 <br>

#### TransactionUtils
事务工具类，用于生成 TransactionDefinition  <br>

