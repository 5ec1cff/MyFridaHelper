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
        s += `  ${stacks[i].toString()}${i!=stacks.length-1?'\n':''}`;
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

function getCFFromCLObject(clObj: any): Java.ClassFactory {
    const CL = new Java.ClassFactory();
    (CL as any).loader = clObj;
    return CL;
}

function getClassWrapperFromClassObject(classObj: any): Java.Wrapper {
    return getCFFromCLObject(classObj.getClassLoader()).use(classObj.getName());
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

function isJavaWrapper(v: any) {
    return v.$h !== undefined;
}

// class accessor

function isStartWithUpperCase(s: string): boolean {
    let t = s.charCodeAt(0);
    return t >= 65 && t <= 90;
}

function classAccessorFactory(_name: string, _classFactory: Java.ClassFactory|null=null): any {
    let name: string;
    if (_name == '') {
        name = '';
    } else {
        name = _name + '.';
    }
    let classFactory: Java.ClassFactory;
    if (_classFactory == null) classFactory = Java.classFactory;
    else classFactory = _classFactory;
    return new Proxy({}, {
        get(t, p, r) {
            if (typeof p == "symbol") throw new Error('symbol is not supported');
            if (p == 'toJSON') return () => `<package: ${name}, cl=${classFactory.loader||'(default)'}>`;
            if (p.startsWith('$')) {
                if (p[1] == 'c') {
                    return classFactory.use(`${name}${p.slice(2)}`);
                } else if (p[1] == 'p') {
                    return classAccessorFactory(`${name}${p.slice(2)}`, classFactory);
                } else if (p[1] == 'u') {
                    return (x: string) => classFactory.use(`${name}${x}`)
                }
            }
            if (isStartWithUpperCase(p)) {
                return classFactory.use(`${name}${p}`);
            } else {
                return classAccessorFactory(`${name}${p}`, classFactory);
            }
        }
    })
}

function use(v: any, enforceClass: boolean=false, enforcePackage: boolean=false): any {
    if (v === undefined) {
        return classAccessorFactory('');
    }
    else if (typeof v == 'string') {
        if (v.indexOf('/') >= 0) v = v.replace(/\//g, '.');
        if (!enforcePackage && (enforceClass || isStartWithUpperCase(v.split('.').slice(-1)[0]))) return Java.use(v);
        return classAccessorFactory(v);
    } else if (v instanceof Java.ClassFactory) {
        return classAccessorFactory('', v);
    } else if (isJavaWrapper(v)) {
        if (isInstance(Java.use('java.lang.Class'), v)) {
            return getClassWrapperFromClassObject(v);
        } else if (isInstance(Java.use('java.lang.ClassLoader'), v)) {
            return classAccessorFactory('', getCFFromCLObject(v));
        }
    }
    throw new Error('unknown type');
}

export {
    getStackTrace,
    printStackTrace,
    printNStackTrace,
    castSelf,
    isInstance,
    catchJvmException,
    getCFFromCLObject,
    getClassWrapperFromClassObject,
    getJavaThreads,
    getMainThread,
    isJavaWrapper,
    use
}
