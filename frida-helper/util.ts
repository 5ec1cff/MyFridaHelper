import * as CM from './class-manager'

const api: CM.ClassSet = {
    Object: CM.Stub("java.lang.Object"),
    Throwable: CM.Stub('java.lang.Throwable'),
    Array: CM.Stub('java.lang.reflect.Array'),
    Thread: CM.Stub('java.lang.Thread'),
}

CM.register(api);

function getStackTrace() {
    if (api.Throwable == null) {
        throw new Error('not initialized');
    }
    let obj = api.Throwable.$new();
    return obj.getStackTrace();
}

function getStackTraceStr(stacks: any) {
    let s = '';
    for (let i = 0; i < stacks.length; i++) {
        s += `  ${stacks[i].toString()}\n`;
    }
    return s;
}

function printStackTrace() {
    let stacks = getStackTrace();
    console.log(getStackTraceStr(stacks));
}

function printNStackTrace(stacks: any) {
    try {
        if (stacks?.$h) {
            let a = [];
            for (let i = 0; i < api.Array.getLength(stacks); i++) {
                a.push(api.Array.get(stacks, i));
            }
            stacks = a;
        }
        console.log(getStackTraceStr(stacks));
    } catch (e: any) {
        console.error('failed to print stack trace', e.stack);
    }
}

function castSelf(x: any) {
    // return Java.cast(x, Java.use(x.$className));
    const CL = new Java.ClassFactory();
    (CL as any).loader = api.Object.getClass.call(x).getClassLoader();
    return CL.cast(x, CL.use(x.$className));
}

function getClassWrapperFromClassObject(classObj: any): Java.Wrapper {
    const CL = new Java.ClassFactory();
    (CL as any).loader = classObj.getClassLoader();
    return CL.use(classObj.getName());
}

function isInstance(klass: any, object: any) {
    return klass?.class.isInstance(object);
}

function catchJvmException(runnable: Function, ...args: any) {
    try {
        runnable(...args);
    } catch (E) {
        let e = E as any;
        if (e.$h != null) {
            try {
                let stack = Java.cast(e.$h, api.Throwable);
                console.error(getStackTraceStr(stack));
            } catch {
                console.error('failed to dump stack from java');
            }
            throw E;
        } else {
            throw e;
        }
    }
    return null;
}

function getJavaThreads() {
    return api.Thread.getAllStackTraces().keySet().toArray();
}

function getMainThread() {
    let threads = getJavaThreads();
    for (let thread of threads) {
        thread = Java.cast(thread, api.Thread);
        if (thread.getName() == 'main') return thread;
    }
    return null;
}

export {
    getStackTrace,
    printStackTrace,
    printNStackTrace,
    castSelf,
    isInstance,
    catchJvmException,
    getClassWrapperFromClassObject,
    getJavaThreads,
    getMainThread
}