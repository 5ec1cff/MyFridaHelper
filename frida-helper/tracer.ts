import * as util from "./util"
import * as CM from './class-manager'

const api: CM.ClassSet = {
    Object: CM.Stub("java.lang.Object"),
    HashMap: CM.Stub('java.util.HashMap'),
    Array: CM.Stub('java.lang.reflect.Array'),
    Thread: CM.Stub('java.lang.Thread'),
    Handler: CM.Stub('android.os.Handler'),
    MessageQueue: CM.Stub('android.os.MessageQueue'),
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
let handlerHooked = false;
let handlerRunning = false;

const ThreadToMsg = api.HashMap.$new();
const MsgToTraceNode = api.HashMap.$new();

function startHookHandler() {
    if (handlerHooked) return;
    console.warn('start hook handler');
    api.MessageQueue.enqueueMessage.implementation = function (msg: any, uptime: any) {
        if (handlerRunning) {
            let node = new TraceNode();
            node.stack = util.getStackTrace();
            node.prev = MsgToTraceNode.get(ThreadToMsg.get(api.Thread.currentThread()));
            // console.warn(node.obj);
            MsgToTraceNode.put(msg, node.obj);
        }
        return this.enqueueMessage(msg, uptime);
    }

    api.Handler.dispatchMessage.implementation = function (msg: any) {
        if (handlerRunning) {
            ThreadToMsg.put(api.Thread.currentThread(), msg);
        }
        this.dispatchMessage(msg);
    }

    handlerHooked = true;
    handlerRunning = true;
}

function unhookHandler() {
    if (!handlerHooked) return;
    console.warn('stop hook handler');
    // api.MessageQueue.enqueueMessage.implementation = null;
    // api.Handler.dispatchMessage.implementation = null;
    // handlerHooked = false;
    handlerRunning = false;
    ThreadToMsg.clear();
    MsgToTraceNode.clear();
}

function incHookHandler() {
    hookCount += 1;
    if (hookCount > 0) {
        startHookHandler();
    }
}

function decHookHandler() {
    hookCount -= 1;
    if (hookCount <= 0) {
        unhookHandler();
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

function traceMethod(method: any, traceHandler: boolean=false, printArgs: boolean=true, printResult: boolean=true, printStack:boolean = true): Function {
    method.implementation = function (...args: any) {
        let threadSelf = api.Thread.currentThread();
        console.log(`method ${method?.holder?.$className||'<unknown>'}#${method?.methodName} called @ ${threadSelf}`);
        if (printArgs) {
            let i = 0;
            for (let type of method.argumentTypes) {
                dumpObj(`arg${i}`, args[i], type);
                i++;
            }
        }
        if (printStack) {
            util.printStackTrace();
            if (traceHandler) {
                let trace = new TraceNode(MsgToTraceNode.get(ThreadToMsg.get(threadSelf)));
                while (true) {
                    console.log('===========from handler:');
                    util.printNStackTrace(trace.stack);
                    if (trace.prev == null) break;
                    trace = new TraceNode(trace.prev);
                }
            }
            console.log('');
        }
        let ret = method.call(this, ...args);
        if (printResult) {
            dumpObj(`result`, ret, method.returnType);
        }
        return ret;
    }
    if (traceHandler) {
        incHookHandler();
    }
    return () => {
        method.implementation = null;
        if (traceHandler) {
            decHookHandler();
        }
    }
}

export {
    traceMethod
}