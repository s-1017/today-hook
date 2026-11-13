// 诊断专用：只记录，不改变任何行为
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static NSString *const kLogPath = @"/var/mobile/Media/xq_diag.log";

static void DLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSDateFormatter *f = [[NSDateFormatter alloc] init];
    f.dateFormat = @"HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n",
                      [f stringFromDate:[NSDate date]], msg];
    FILE *fp = fopen(kLogPath.UTF8String, "a");
    if (fp) { fputs(line.UTF8String, fp); fclose(fp); }
    NSLog(@"[XQDiag] %@", msg);
}

static void DumpWindows(NSString *why) {
    NSMutableString *buf = [NSMutableString string];
    [buf appendFormat:@"--- %@ ---\n", why];
    if (@available(iOS 13.0, *)) {
        int si = 0;
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            NSUInteger wc = [sc isKindOfClass:[UIWindowScene class]]
                          ? ((UIWindowScene *)sc).windows.count : 0;
            [buf appendFormat:@"  scene#%d %s state=%ld windows=%lu\n", si++,
             NSStringFromClass([sc class]).UTF8String, (long)sc.activationState,
             (unsigned long)wc];
        }
    }
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        [buf appendFormat:@"  win %-26s level=%.0f hidden=%d key=%d alpha=%.2f root=%-24s scene=%d\n",
         NSStringFromClass([w class]).UTF8String, (double)w.windowLevel, (int)w.hidden,
         (int)w.isKeyWindow, (double)w.alpha,
         w.rootViewController ? NSStringFromClass([w.rootViewController class]).UTF8String : "nil",
         w.windowScene != nil];
    }
    DLog(@"%@", buf);
}

static void (*orig_mkv)(id, SEL) = NULL;
static void my_mkv(id self, SEL _cmd) {
    if (orig_mkv) orig_mkv(self, _cmd);
    DLog(@"makeKeyAndVisible: %s", NSStringFromClass([self class]).UTF8String);
    DumpWindows(@"after makeKeyAndVisible");
}

static void (*orig_sh)(id, SEL, BOOL) = NULL;
static void my_sh(id self, SEL _cmd, BOOL h) {
    if (orig_sh) orig_sh(self, _cmd, h);
    if (h == NO) DLog(@"setHidden(NO): %s", NSStringFromClass([self class]).UTF8String);
}

// viewDidLoad（无参数）
static IMP orig_hud_vdl = NULL;
static void my_hud_vdl(id self, SEL _cmd) {
    ((void (*)(id, SEL))orig_hud_vdl)(self, _cmd);
    DLog(@"HUD viewDidLoad: %s", NSStringFromClass([self class]).UTF8String);
    DumpWindows(@"after HUD viewDidLoad");
}

// viewWillAppear: / viewDidAppear:（BOOL 参数）
static IMP orig_hud_vwa = NULL;
static void my_hud_vwa(id self, SEL _cmd, BOOL animated) {
    ((void (*)(id, SEL, BOOL))orig_hud_vwa)(self, _cmd, animated);
    DLog(@"HUD %s: %s", sel_getName(_cmd), NSStringFromClass([self class]).UTF8String);
    DumpWindows(@"after HUD appear");
}

static void hookVoid(const char *cls, SEL sel, IMP newImp, IMP *store, const char *tag) {
    Class c = objc_getClass(cls);
    if (!c) { DLog(@"类不存在: %s", cls); return; }
    Method m = class_getInstanceMethod(c, sel);
    if (!m) { DLog(@"方法不存在: %s %s", cls, tag); return; }
    *store = method_getImplementation(m);
    method_setImplementation(m, newImp);
    DLog(@"已挂钩: %s %s", cls, tag);
}

__attribute__((constructor)) static void xq_diag_init(void) {
    DLog(@"===== diag 启动 =====");
    Class wc = objc_getClass("UIWindow");
    if (wc) {
        Method m1 = class_getInstanceMethod(wc, @selector(makeKeyAndVisible));
        if (m1) { orig_mkv = (void (*)(id, SEL))method_getImplementation(m1);
                  method_setImplementation(m1, (IMP)my_mkv); }
        Method m2 = class_getInstanceMethod(wc, @selector(setHidden:));
        if (m2) { orig_sh = (void (*)(id, SEL, BOOL))method_getImplementation(m2);
                  method_setImplementation(m2, (IMP)my_sh); }
    }
    hookVoid("HUDRootViewController", @selector(viewDidLoad), (IMP)my_hud_vdl,
             &orig_hud_vdl, "viewDidLoad");
    hookVoid("HUDRootViewController", @selector(viewWillAppear:), (IMP)my_hud_vwa,
             &orig_hud_vwa, "viewWillAppear");
    hookVoid("HUDRootViewController", @selector(viewDidAppear:), (IMP)my_hud_vwa,
             &orig_hud_vwa, "viewDidAppear");

    int n = objc_getClassList(NULL, 0);
    Class *list = (Class *)malloc(sizeof(Class) * n);
    objc_getClassList(list, n);
    NSMutableString *hudCls = [NSMutableString string];
    NSMutableString *winCls = [NSMutableString string];
    for (int i = 0; i < n; i++) {
        NSString *nm = NSStringFromClass(list[i]);
        if ([nm containsString:@"HUD"]) [hudCls appendFormat:@"%@ ", nm];
        if ([nm containsString:@"Window"] && [nm containsString:@"Main"])
            [winCls appendFormat:@"%@ ", nm];
    }
    free(list);
    DLog(@"含 HUD 的类: %@", hudCls);
    DLog(@"含 Main/Window 的类: %@", winCls);
    DLog(@"===== diag 就绪 =====");
}
