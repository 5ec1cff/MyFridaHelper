import * as util from "./util"
import * as CM from './class-manager'

let is_init = false;

const api: CM.ClassSet = {
    ViewGroup: CM.Stub("android.view.ViewGroup"), 
    View: CM.Stub("android.view.View"), 
    ActivityThread: CM.Stub("android.app.ActivityThread"), 
    ViewRootImpl: CM.Stub("android.view.ViewRootImpl"), 
    ViewRootImpl_W: CM.Stub("android.view.ViewRootImpl$W"), 
    TextView: CM.Stub("android.widget.TextView"), 
    ActivityClientRecord: CM.Stub("android.app.ActivityThread$ActivityClientRecord"), 
    Resources: CM.Stub("android.content.res.Resources"), 
    ARect: CM.Stub("android.graphics.Rect"), 
    ARectF: CM.Stub("android.graphics.RectF"), 
    APaint: CM.Stub("android.graphics.Paint"), 
    APaintStyle: CM.Stub("android.graphics.Paint$Style"), 
    AMotionEvent: CM.Stub("android.view.MotionEvent"), 
}

CM.register(api);

const VIEW_NO_ID = -1;

let is_debug = true;

const CONSOLE = {
    log(...args: any) {
        if (is_debug) {
            console.log(...args)
        }
    },
    error(...args: any) {
        console.error(...args)
    },
    warn(...args: any) {
        if (is_debug) {
            console.warn(...args)
        }
    }
}

interface Rect {
    left: number,
    right: number,
    top: number,
    bottom: number
}

interface QueryParams {
    id?: number | string,
    class?: string | RegExp | any,
    parentClass?: string | RegExp | any,
    text?: string | RegExp,
    maxDepth?: number,
    limit?: number,
    boundsIn?: Rect | Array<number>
}

type SelectCallback = (result: Rect) => void

class ResourceId {
    _pkg: string;
    _typ: string;
    _ent: string;
    constructor(pkg: string, type: string, entry: string) {
        this._pkg = pkg; this._typ = type; this._ent = entry;
    }
    get package(): string {
        return this._pkg;
    }
    get type(): string {
        return this._typ;
    }
    get entry(): string {
        return this._ent;
    }
    flatten(): string {
        return `${this._pkg}:${this._typ}/${this._ent}`;
    }
}

function ARectToRect(rect: any): Rect {
    return {
        left: rect.left.value,
        right: rect.right.value,
        top: rect.top.value,
        bottom: rect.bottom.value
    };
}

function RectToARect(rect: Rect): any {
    return api.ARect.$new(rect.left, rect.top, rect.right, rect.bottom);
}

function RectToARectF(rect: Rect): any {
    return api.ARectF.$new(rect.left, rect.top, rect.right, rect.bottom);
}

function arrayToRect([l, t, r, b]: Array<number>): Rect {
    return {
        left: l, top: t, right: r, bottom: b
    };
}

function toRightRect(r: Rect): Rect {
    let newRect = Object.assign({}, r);
    if (newRect.left > newRect.right) {
        let t = newRect.left; newRect.left = newRect.right; newRect.right = t;
    }
    if (newRect.top > newRect.bottom) {
        let t = newRect.top; newRect.top = newRect.bottom; newRect.bottom = t;
    }
    return newRect;
}

class ViewHook {
    mMarkedViews: Set<ViewWrapper> = new Set();
    mSelectedModeView: ViewWrapper | null = null;
    mSelectionRect: Rect | null = null;
    mSelectCallBack: SelectCallback | null = null;
    mPaint: any;

    #isDrawHooked: boolean = false;
    #isTouchHooked: boolean = false;

    #lastHookedViewClass: any;

    constructor() {
        let paint = api.APaint.$new();
        api.APaint.setColor.overload('int').call(paint, 0xff00ff00);
        paint.setStyle(api.APaintStyle.STROKE.value);
        this.mPaint = paint;
    }

    #updateDrawHook() {
        if (this.mMarkedViews.size <= 0 && this.mSelectedModeView == null) {
            api.View.draw.overload('android.graphics.Canvas').implementation = null;
            this.#isDrawHooked = false;
        } else if (!this.#isDrawHooked) {
            // console.warn('hooked draw');
            const hooker = this;
            api.View.draw.overload('android.graphics.Canvas').implementation = function (...args: any) {
                this.draw(...args);
                let shouldMark = false, shouldDrawRect = false;
                if (hooker.mSelectedModeView != null && this.equals(hooker.mSelectedModeView.view)) {
                    shouldMark = true;
                    shouldDrawRect = true;
                }
                for (let v of hooker.mMarkedViews) {
                    if (this.equals(v.view)) {
                        // console.log('marked');
                        shouldMark = true;
                        break;
                    }
                }
                let canvas = args[0];
                if (shouldMark) {
                    canvas.drawARGB(100, 255, 0, 0);
                }
                if (shouldDrawRect && hooker.mSelectionRect != null) {
                    console.warn('draw rect');
                    canvas.drawRect(RectToARectF(hooker.mSelectionRect), hooker.mPaint);
                }
            }
            this.#isDrawHooked = true;
        }
    }

    #updateTouchHook() {
        if (this.mSelectedModeView == null) {
            // unhook
            this.#isTouchHooked = false;
            if (this.#lastHookedViewClass != null) {
                this.#lastHookedViewClass.dispatchTouchEvent.overload('android.view.MotionEvent').implementation = null;
            }
        } else if (!this.#isTouchHooked) {
            // hook
            const klass = util.getClassWrapperFromClassObject(this.mSelectedModeView.view.getClass());
            if (this.#lastHookedViewClass != null) {
                this.#lastHookedViewClass.dispatchTouchEvent.overload('android.view.MotionEvent').implementation = null;
            }
            CONSOLE.warn('hooked class:', klass.class.getName());
            const hooker = this;
            klass.dispatchTouchEvent.overload('android.view.MotionEvent').implementation = function (event: any) {
                if (!hooker.#isTouchHooked || (hooker.mSelectedModeView != null && !this.equals(hooker.mSelectedModeView.view))) return this.dispatchTouchEvent(event);
                const action = event.getActionMasked();
                let x = event.getX(), y = event.getY();
                // CONSOLE.warn(`got x and y: ${x}, ${y}`);
                if (typeof x != "number" && typeof y != "number") {
                    return true;
                }
                if (action == api.AMotionEvent.ACTION_DOWN.value) {
                    CONSOLE.warn('start selection');
                    hooker.mSelectionRect = {
                        left: x, right: x, top: y, bottom: y
                    };
                } else if (action == api.AMotionEvent.ACTION_MOVE.value) {
                    if (hooker.mSelectionRect != null) {
                        hooker.mSelectionRect.right = x;
                        hooker.mSelectionRect.bottom = y;
                    }
                } else if (action == api.AMotionEvent.ACTION_UP.value) {
                    CONSOLE.warn('end selection');
                    if (hooker.mSelectionRect != null) {
                        hooker.mSelectionRect.right = x;
                        hooker.mSelectionRect.bottom = y;
                        try {
                            if (hooker.mSelectCallBack != null) {
                                hooker.mSelectCallBack(hooker.mSelectionRect);
                            }
                        } catch (e: any) {
                            CONSOLE.error('error while callback', e.stack);
                        }
                    }
                    CONSOLE.warn('last rect:', JSON.stringify(hooker.mSelectionRect));
                    hooker.mSelectionRect = null;
                    hooker.mSelectedModeView = null;
                    hooker.#isTouchHooked = false;
                }
                if (hooker.mSelectedModeView != null)
                    hooker.mSelectedModeView.invalidate();
                // hooker.#updateTouchHook();
                return true;
            }
            this.#lastHookedViewClass = klass;
            this.#isTouchHooked = true;
        }
        this.#updateDrawHook();
    }
    
    addMark(v: ViewWrapper) {
        this.mMarkedViews.add(v);
        this.#updateDrawHook();
        v.prepareForHookDraw();
    }

    delMark(v: ViewWrapper) {
        this.mMarkedViews.delete(v);
        this.#updateDrawHook();
        v.invalidate();
    }

    hasMark(v: ViewWrapper): boolean {
        return this.mMarkedViews.has(v);
    }

    enterSelection(v: ViewWrapper, callback?:SelectCallback) {
        if (this.mSelectedModeView != null)
            throw new Error('not now!');
        this.mSelectedModeView = v;
        this.mSelectCallBack = null;
        if (callback != null)
            this.mSelectCallBack = callback;
        this.#updateTouchHook();
        v.prepareForHookDraw();
    }

    showBorder(b: boolean) {
        api.View.DEBUG_DRAW.value = Boolean(b);
    }
}

class ViewWrapper {
    view: any = null;
    _is_group:boolean|null = null;

    constructor(obj: any) {
        if (!is_init) {
            throw new Error("failed to get wrapper: not init");
        }
        if (obj == null) {
            throw new Error("view is null");
        }
        this.view = Java.cast(obj, api.View) as any;
    }

    get id(): number {
        return api.View.getId.call(this.view);
    }

    get resourceId(): ResourceId | null {
        let id: number = this.id;
        if (id != VIEW_NO_ID) {
            let mResources = this.view.mResources.value, pkgName, typeName, entryName;
            if (id > 0 && api.Resources.resourceHasPackage(id) && mResources != null) {
                try {
                    mResources = Java.cast(mResources, api.Resources);
                    switch (id & 0xff000000) {
                        case 0x7f000000:
                            pkgName = "app";
                            break;
                        case 0x01000000:
                            pkgName = "android";
                            break;
                        default:
                            pkgName = mResources.getResourcePackageName(id);
                            break;
                    }
                    typeName = mResources.getResourceTypeName(id);
                    entryName = mResources.getResourceEntryName(id);
                    return new ResourceId(pkgName, typeName, entryName);
                } catch (e) {
                    console.warn('failed to get resource: ', e);
                }
            }
        }
        return null;
    }

    toString(): string {
        return `ViewWrapper{${this.view.toString()}}`;
    }

    get text(): string | null {
        if(api.TextView.class.isInstance(this.view)) {
            return api.TextView.getText.call(this.view).toString();
        }
        return null;
    }

    get isViewGroup(): boolean {
        if (this._is_group == null) {
            this._is_group = api.ViewGroup.class.isInstance(this.view);
        }
        return this._is_group as boolean;
    }

    static _ensureViewGroup(thiz: ViewWrapper, msg: string) {
        if (!thiz.isViewGroup) {
            throw new Error(msg);
        }
    }

    at(i: number): ViewWrapper {
        ViewWrapper._ensureViewGroup(this, "at: ViewGroup needed");
        return new ViewWrapper(api.ViewGroup.getChildAt.call(this.view, i));
    }

    get count(): number {
        ViewWrapper._ensureViewGroup(this, "count: ViewGroup needed");
        return api.ViewGroup.getChildCount.call(this.view);
    }

    get children(): Array<ViewWrapper> {
        ViewWrapper._ensureViewGroup(this, "children: ViewGroup needed");
        let result: Array<ViewWrapper> = [];
        for (let i = 0; i < this.count; i++) {
            result.push(this.at(i));
        }
        return result;
    }

    get parent(): ViewWrapper | any {
        let parent = this.view.getParent();
        if (api.ViewRootImpl.class.isInstance(parent)) {
            return parent;
        }
        return new ViewWrapper(this.view.getParent());
    }

    get attachInfo(): any {
        return this.view.mAttachInfo.value;
    }

    get root(): any {
        return this.attachInfo.mRootView.value;
    }

    get vri(): any {
        return this.attachInfo.value.mViewRootImpl.value;
    }

    get bounds(): Rect {
        return this.boundsOnScreen();
    }

    boundsOnScreen(): Rect {
        let rect = api.ARect.$new();
        this.view.getBoundsOnScreen(rect);
        return ARectToRect(rect);
    };

    match(param: QueryParams): boolean {
        if (param.id != null) {
            if (typeof param.id == 'number') {
                if (param.id != this.id) return false;
            } else if (typeof param.id == 'string') {
                if (this.resourceId != null)
                    if (this.resourceId.flatten().indexOf(param.id) < 0) return false;
                else
                    return false;
            }
        }
        if (param.text != null) {
            if (this.text == null) return false;
            if (typeof param.text == 'string') {
                if (this.text.indexOf(param.text) < 0) return false;
            } else if (param.text instanceof RegExp) {
                if (this.text.match(param.text) == null) return false;
            }
        }
        if (param.class != null) {
            if (typeof param.class == 'string') {
                if (this.view.getClass().getName().indexOf(param.class) < 0) return false;
            } else if (param.class instanceof RegExp) {
                if (this.view.getClass().getName().match(param.class) == null) return false;
            } else if (typeof param.class?.class?.isInstance == 'function') { // is a class wrapper
                if (!param.class.class.isInstance(this.view)) return false;
            }
        }
        if (param.parentClass != null) {
            let parentClass = this.view.getClass();
            while (parentClass != null) {
                if (typeof param.parentClass == 'string') {
                    if (this.view.getClass().getName().indexOf(param.parentClass) >= 0) return true;
                } else if (param.parentClass instanceof RegExp) {
                    if (this.view.getClass().getName().match(param.parentClass) != null) return true;
                } else if (typeof param.parentClass?.class?.isInstance == 'function') { // is a class wrapper
                    if (param.parentClass.class.isInstance(this.view)) return true;
                }
                parentClass = parentClass.getSuperclass();
            }
            return false;
        }
        if (param.boundsIn != null) {
            let r = this.bounds, q = param.boundsIn;
            if (q instanceof Array) {
                q = arrayToRect(q);
            }
            q = toRightRect(q);
            if (!(r.left >= q.left && r.right <= q.right && r.top >= q.top && r.bottom <= q.bottom)) return false;
        }
        return true;
    }

    find(param: QueryParams): ViewWrapper | Array<ViewWrapper> | null {
        let newParam: QueryParams = {};
        Object.assign(newParam, param);
        if (newParam.limit == null) {
            newParam.limit = 1;
        }
        if (newParam.maxDepth == null) {
            newParam.maxDepth = Infinity;
        }
        if (newParam.maxDepth == 0) {
            return null;
        }
        let list: Array<ViewWrapper> = [];
        this._find(newParam, list, 0);
        if (list.length == 0) return null;
        if (newParam.limit == 1) return list[0];
        else return list.slice(0, newParam.limit);
    }

    _find(param: QueryParams, list: Array<ViewWrapper>, depth: number): boolean {
        if (depth >= (param.maxDepth as number)) return false;
        if (list.length >= (param.limit as number)) return false;
        if (this.match(param)) list.push(this);
        if (!this.isViewGroup) return true;
        for (let child of this.children) {
            if (!child._find(param, list, depth + 1)) break;
        }
        return true;
    }

    _logTree(lvl: number, prefix: string, log: Function) {
        log(`${prefix} ${this.view?.toString()}`);
        let text = this.text;
        if (text) {
            log(`${' '.repeat(prefix.length)} text=${text}`);
        }
        if (this.isViewGroup) {
            if (lvl == 0) {
                log(`${' '.repeat(prefix.length)} (${this.count} childrens ...)`);
                return;
            }
            let i = 0, len = String(this.count - 1).length;
            for (let child of this.children) {
                let childPrefix = String(i).padStart(len, ' ');
                child._logTree(lvl - 1, `${prefix}${childPrefix}|`, log);
                i++;
            }
        }
    }

    logTree(maxlvl: number = 5, method: string='warn') {
        const logMethod = (console as any)[method];
        if (typeof logMethod != "function") {
            throw new Error(`console.${method} is not a function!`);
        }
        this._logTree(maxlvl, "", logMethod);
    }

    /**
     * @description Re-draw this View
     */
    invalidate() {
        Java.scheduleOnMainThread(() => {
            this.view.invalidate();
        })
    }

    /**
     * @description Re-draw the root of this View
     */
    invalidateRoot() {
        Java.scheduleOnMainThread(() => {
            this.vri.invalidateWorld(this.root);
        })
    }

    /**
     * @description Ensure that hooking View.draw makes effect
     */
    prepareForHookDraw() {
        Java.scheduleOnMainThread(() => {
            this.view.setFlags(0, api.View.PFLAG_SKIP_DRAW.value);
            this.view.invalidate();
        })
    }

    /**
     * @description The switch of this View's mark
     * @todo customize mark style
     */
    mark() {
        let hook:ViewHook = V.getViewHook();
        if (hook.hasMark(this)) {
            console.warn('mark off');
            hook.delMark(this);
        } else {
            console.warn('mark on');
            hook.addMark(this);
        }
    }

    /**
     * @description Enter selection mode for this view.
     * @param cb Selection callback, will pass the selected rect
     */
    select(cb?: SelectCallback) {
        V.getViewHook().enterSelection(this, cb);
    }

    capture() {}

    // like `toString` but in CLI
    toJSON(): string {
        return this.toString();
    }
}

class V {
    static _init (){
        // console.log('libview init...');
        /*
        let default_wm = Java.use('android.view.WindowManagerGlobal').sDefaultWindowManager.value,
            mViews = default_wm.mViews.value;

        let activityThread = ActivityThread.currentActivityThread(),
            mActivities = activityThread.mActivities.value;

        V.$sDefaultWindowManager = default_wm;
        V.$mViews = mViews;
        V.$currentActivityThread = activityThread;
        V.$mActivities = mActivities;
        V.wmg = default_wm;*/
        is_init = true;
        console.log('libview initialized');
    }

    static get wmg(): any {
        return Java.use('android.view.WindowManagerGlobal').sDefaultWindowManager.value;
    }

    static get activityThread(): any {
        return api.ActivityThread.currentActivityThread();
    }

    static get activities(): any {
        return V.activityThread.mActivities.value;
    }

    static get roots(): any {
        return V.wmg.mRoots.value.toArray().map((x: any) => util.castSelf(x));
    }

    static get params(): any {
        return V.wmg.mParams.value.toArray().map((x: any) => util.castSelf(x));
    }

    static get views(): any {
        return V.wmg.mViews.value.toArray().map((x: any) => util.castSelf(x));
    }

    static getText(view: any) {
        if(api.TextView.class.isInstance(view)) {
            return api.TextView.getText.call(view).toString();
        }
        return '';
    }

    static logViewTree(view:any, cnt=0, lvl=1, maxlvl=0) {
        let v = Java.cast(view, api.View);
        console.log(`${'|'.repeat(lvl)}${cnt} ${v.toString()}`)
        let extras = {
            'id': (() => {
                let id = v.getId();
                if (id == -1)
                    return null;
                return id;
            })(),
            'text': V.getText(view)
        } as any, extlog = ''
        for (let k in extras) {
            if (extras[k]) {
                extlog += ` ${k}=${extras[k]}`
            }
        }
        if (extlog)
            console.log(`${' '.repeat(lvl)}${extlog}`);
        if (api.ViewGroup.class.isInstance(view)) {
            let group = Java.cast(view, api.ViewGroup);
            if (maxlvl > 0 && lvl >= maxlvl) {
                console.log('  '.repeat(lvl) + ` has ${group.getChildCount()} children (max level reached)`)
                return;
            }
            for (let i = 0; i < group.getChildCount(); i++) {
                V.logViewTree(group.getChildAt(i), i, lvl + 1, maxlvl);
            }
        }
    }

    static forEachActivities(m: any, cb: Function) {
        let keys = m.keySet().toArray();
        for (let i = 0;i < keys.length; i++) {
            var r;
            if ((r = cb(keys[i], m.get(keys[i]), i)) != undefined)
                return r;
        }
        return null;
    }

    static getCurrentActivityRecord() {
        return V.forEachActivities(V.activities, (k: any, v: any) => {
            let acr = Java.cast(v, api.ActivityClientRecord);
            if (!acr.paused.value) {
                return acr;
            }
        });
    }

    static getCurrentActivity() {
        let a = V.getCurrentActivityRecord();
        if (a) {
            return a.activity.value;
        }
        return null;
    }
    static getCurrentActivityRootView(){
        let a = V.getCurrentActivity();
        if (a) {
            return a.getWindow().getDecorView();
        }
        return null;
    }

    // new

    static currentRoot(): ViewWrapper {
        return new ViewWrapper(V.getCurrentActivityRootView());
    }

    static currentFocus(): any {
        let result = [];
        for (let vri of V.roots) {
            if (vri.mAttachInfo.value.mHasWindowFocus.value) {
                result.push(new ViewWrapper(vri.mView.value));
            }
        }
        if (result.length > 1) {
            console.warn('more than 1 focused window!');
            return result;
        } else if (result.length == 1) {
            return result[0];
        }
        console.warn('no focused window found!');
    }

    static getViewRootImpl(decorView: any): any {
        let wt = util.castSelf(decorView).getWindowToken();
        let va = util.castSelf(wt).mViewAncestor.value.get();
        return util.castSelf(va);
    }

    /**
     * @description return initial application
     */
    static get app(): any {
        return util.castSelf(api.ActivityThread.currentActivityThread().mInitialApplication.value);
    }

    static viewHook:ViewHook ;

    static getViewHook(): ViewHook {
        if (V.viewHook == null) {
            V.viewHook = new ViewHook();
        }
        return this.viewHook;
    }

    static setIsDebug(b: boolean) {
        is_debug = b;
    }

    static showBorder(b?: boolean) {
        if (b == undefined) b = true;
        V.getViewHook().showBorder(b);
        V.currentRoot().invalidateRoot();
    }
}

Java.perform(V._init);

export {
    V as LibView,
    ViewWrapper
}