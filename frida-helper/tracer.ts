import * as util from "./util"
import * as CM from './class-manager'

const api: CM.ClassSet = {
    Object: CM.Stub("java.lang.Object"),
    HashMap: CM.Stub('java.util.HashMap'),
    Array: CM.Stub('java.lang.reflect.Array'),
    Thread: CM.Stub('java.lang.Thread'),
    Handler: CM.Stub('android.os.Handler'),
    MessageQueue: CM.Stub('android.os.MessageQueue'),
    Throwable: CM.Stub('java.lang.Throwable'),
}

CM.register(api);

class TraceNode {
    obj: any = null
    constructor(obj: any=null) {
        if (obj) this.obj = obj;
        else this.obj = api.Array.newInstance(api.Object.class, 2);
    }

    set stack(t: any) {
        if (t.$w) t = t.$w;
        api.Array.set(this.obj, 0, t);
    }

    get stack(): any {
        return api.Array.get(this.obj, 0);
    }

    set prev(t: any) {
        // console.log(this.obj, t)
        api.Array.set(this.obj, 1, t);
    }

    get prev(): any {
        return api.Array.get(this.obj, 1);
    }
}

let hookCount = 0;
let msgQHooked = false;
let handlerRunning = false;

const ThreadToMsg = api.HashMap.$new();
const MsgToTraceNode = api.HashMap.$new();

function startHookMessageQueue() {
    if (msgQHooked) return;
    console.warn('start hook handler');
    api.MessageQueue.enqueueMessage.implementation = function (msg: any, uptime: any) {
        if (handlerRunning) {
            let stack = util.getStackTrace();
            // only record msg from handler
            if (stack?.length >= 1 && stack[1]?.getClassName() == 'android.os.Handler') {
                let node = new TraceNode();
                node.stack = stack;
                node.prev = MsgToTraceNode.get(ThreadToMsg.get(api.Thread.currentThread()));
                MsgToTraceNode.put(msg, node.obj);
            }
        }
        return this.enqueueMessage(msg, uptime);
    }

    api.Handler.dispatchMessage.implementation = function (msg: any) {
        if (handlerRunning) {
            ThreadToMsg.put(api.Thread.currentThread(), msg);
        }
        try {
            this.dispatchMessage(msg);
        } finally {
            ThreadToMsg.remove(api.Thread.currentThread());
        }
    }

    msgQHooked = true;
    handlerRunning = true;
}

function stopHookMessageQueue() {
    if (!msgQHooked) return;
    console.warn('stop hook handler');
    // api.MessageQueue.enqueueMessage.implementation = null;
    // api.Handler.dispatchMessage.implementation = null;
    // handlerHooked = false;
    handlerRunning = false;
    ThreadToMsg.clear();
    MsgToTraceNode.clear();
}

function incMsgQHook() {
    hookCount += 1;
    if (hookCount > 0) {
        startHookMessageQueue();
    }
}

function decMsgQHook() {
    hookCount -= 1;
    if (hookCount <= 0) {
        stopHookMessageQueue();
    }
}

function dumpObj(name: string, val: any, type: any) {
    let isObj = typeof val?.getClass == 'function';
    let value;
    if (val == null) value = null;
    else {
        try {
            value = val.toString();
        } catch (e) {
            try {
                value = api.Object.toString.call(e);
            } catch (e) {
                value = '(unknown or null)';
            }
        }
    }
    console.log(`${name}: type=${type?.className}, realType=${isObj?'class:'+val.getClass()?.getName():('prim:'+typeof val)}, value=${value}`);
}

function traceMethod(method: any, traceHandler: boolean=false, printArgs: boolean=true, printResult: boolean=true, printStack:boolean = true, printThis: boolean = true): Function {
    method.implementation = function (...args: any) {
        let threadSelf = api.Thread.currentThread();
        console.log(`method ${method?.holder?.$className||'<unknown>'}#${method?.methodName} called @ ${threadSelf}`);
        if (printThis && this != null) {
            dumpObj('this', this, {type: ""});
        }
        if (printArgs) {
            let i = 0;
            for (let type of method.argumentTypes) {
                dumpObj(`arg${i}`, args[i], type);
                i++;
            }
        }
        let ret, ex;
        try {
            ret = method.call(this, ...args);
        } catch (e: any) {
            if (e.$h) {
                ex = e;
            } else {
                console.error("error occured", e.stack);
            }
        }
        if (printResult) {
            if (ret !== undefined) {
                dumpObj(`result`, ret, method.returnType);
            } else if (ex !== undefined) {
                ex = Java.cast(ex, api.Throwable);
                console.error("Java error occured while invoke original method", ex?.getClass()?.getName(), ex.getMessage());
            }
        }
        if (printStack) {
            util.printStackTrace();
            if (traceHandler) {
                let trace = new TraceNode(MsgToTraceNode.get(ThreadToMsg.get(threadSelf)));
                while (true) {
                    console.log('  (Handler message)');
                    util.printNStackTrace(trace.stack);
                    if (trace.prev == null) break;
                    trace = new TraceNode(trace.prev);
                }
            }
            console.log('');
        }
        
        if (ex) {
            throw ex;
        } else {
            return ret;
        }
    }
    if (traceHandler) {
        incMsgQHook();
    }
    return () => {
        method.implementation = null;
        if (traceHandler) {
            decMsgQHook();
        }
    }
}

export {
    traceMethod
}