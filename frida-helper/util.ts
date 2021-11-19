const api = {
    Throwable: null as any,
    Object: null as any
};

function init() {
    Java.perform(() => {
        api.Throwable = Java.use('java.lang.Throwable');
        api.Object = Java.use('java.lang.Object');
    })
}

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

export {
    init,
    getStackTrace,
    printStackTrace,
    castSelf,
    isInstance,
    catchJvmException,
    getClassWrapperFromClassObject
}