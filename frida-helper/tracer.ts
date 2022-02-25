import * as util from "./util"
import * as CM from './class-manager'

const api: CM.ClassSet = {
    Object: CM.Stub("java.lang.Object"),
    HashMap: CM.Stub('java.util.HashMap'),
    HashSet: CM.Stub('java.util.HashSet'),
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
const ThreadTraceNodeNotUsed = api.HashSet.$new();

function startHookMessageQueue() {
    if (msgQHooked) return;
    ThreadToMsg.clear();
    MsgToTraceNode.clear();
    ThreadTraceNodeNotUsed.clear();
    console.warn('start hook handler');
    api.MessageQueue.enqueueMessage.implementation = function (msg: any, uptime: any) {
        if (handlerRunning) {
            let stack = util.getStackTrace();
            // only record msg from handler
            if (stack?.length >= 1 && stack[1]?.getClassName() == 'android.os.Handler') {
                // create trace node
                let node = new TraceNode();
                node.stack = stack; // take snapshot of stack trace
                // if current thread was bound to a message
                // that we've already taken snapshot, then
                // make it link to current node.
                const thread = api.Thread.currentThread();
                let oldMsg = ThreadToMsg.get(thread);
                if (oldMsg != null) {
                    ThreadTraceNodeNotUsed.remove(thread);
                }
                node.prev = MsgToTraceNode.get(oldMsg);
                // bind current message to trace node
                MsgToTraceNode.put(msg, node.obj);
            }
        }
        return this.enqueueMessage(msg, uptime);
    }

    api.Handler.dispatchMessage.implementation = function (msg: any) {
        const thread = api.Thread.currentThread();
        if (handlerRunning) {
            // bind current thread to message, for our tracer hook
            ThreadToMsg.put(thread, msg);
            ThreadTraceNodeNotUsed.add(thread);
        }
        try {
            this.dispatchMessage(msg);
        } finally {
            ThreadToMsg.remove(thread);
            if (ThreadTraceNodeNotUsed.contains(thread)) {
                // our TraceNode hasn't been used. release it.
                MsgToTraceNode.remove(msg);
                ThreadTraceNodeNotUsed.remove(thread);
            }
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
    ThreadTraceNodeNotUsed.clear();
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
    console.log(`${name}: type=${type?.className}, realType=${isObj?'class:'+val?.getClass()?.getName():('prim:'+typeof val)}, value=${value}`);
}

interface TraceResult {
    this?: any,
    args?: any, 
    result?: any,
    exception?: any
    stack?: any,
    thread?: any,
}

function dumpMethod(method: any) {
    let result = '', l;
    if (l = method._o?.length) {
        result += `${l} overload methods\n`
        for (let i = 0; i < l; i++) {
            let m = method._o[i];
            result += `[${i}] ${dumpMethod(m)}\n`;
        }
        return result;
    }
    if (method._p == null) throw new Error('Not a frida method');
    let p = method?._p, name = p[0], klass = p[1]?.class?.getName(), isStatic = p[2] == 2, ret = p[4]?.className, args = (p[5]?.map((x: any) => x?.className)||['<unknown>']).join(', ');
    return `${isStatic?'static ':''}${ret} ${klass}#${name} (${args})`;
}

function traceMethod(method: any, traceHandler: boolean=false, printArgs: boolean=true, printResult: boolean=true, printStack:boolean = true, printThis: boolean = true): any {
    let l;
    if (l = method._o?.length) {
        console.warn(`Trace ${l} overload methods!`);
        let hooked: any = [];
        hooked.unhook = () => {
            hooked.forEach((m: any) => {
                m.unhook();
            });
        }
        for (let i = 0; i < l; i++) {
            let m = method._o[i], r;
            try {
                r = traceMethod(m, traceHandler, printArgs, printResult, printStack, printThis);
            } catch (e: any) {
                r = null;
            }
            if (r) {
                console.warn(`hook ${dumpMethod(m)} success`);
                hooked.push(r);
            } else {
                console.error(`hook ${dumpMethod(m)} failed`);
            }
        }
        return hooked;
    }
    if (method._p == null) throw new Error('Not a frida method');
    let isStatic = method._p[2] == 2; // static ?
    let traceResult: Array<TraceResult> = [];
    method.implementation = function (...args: any) {
        let threadSelf = api.Thread.currentThread();
        console.log(`[${traceResult.length}] method ${method?.holder?.$className||'<unknown>'}#${method?.methodName} called @ ${threadSelf}`);
        if (printThis) {
            if (!isStatic) dumpObj('this', this, {type: ""});
            else console.log('(static method)');
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
                    console.warn('  <Message dispatch (async)>');
                    util.printNStackTrace(trace.stack);
                    if (trace.prev == null) break;
                    trace = new TraceNode(trace.prev);
                }
            }
            console.log('');
        }

        traceResult.push({
            this: this && Java.retain(this) || null,
            args: args.map((x: any) => x && x.$h && Java.retain(x) || x),
            result: ret && ret.$h && Java.retain(ret) || null,
            exception: ex && ex.$h && Java.retain(ex) || null
        })

        if (traceHandler) {
            ThreadTraceNodeNotUsed.remove(threadSelf);
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
    return {
        method,
        traceResult, 
        unhook() {
            method.implementation = null;
            if (traceHandler) {
                decMsgQHook();
            }
        },
        toJSON() {
            return `<TraceResult (${traceResult.length}) for method ${dumpMethod(method)}>`
        }
    }
}

export {
    traceMethod,
    dumpMethod
}
