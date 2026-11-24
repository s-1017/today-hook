// 菜单探针：dump WDMenuView / WDRow 的真实运行时结构
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static NSString *const kLog = @"/var/mobile/Media/xq_menu.log";

static void L(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *m = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSDateFormatter *f = [NSDateFormatter new];
    f.dateFormat = @"HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n", [f stringFromDate:[NSDate date]], m];
    FILE *fp = fopen(kLog.UTF8String, "a");
    if (fp) { fputs(line.UTF8String, fp); fclose(fp); }
    NSLog(@"%@", line);
}

static void DumpObject(id obj, NSString *tag) {
    if (!obj) { L(@"%@ = nil", tag); return; }
    Class c = object_getClass(obj);
    L(@"==== %@ (%@) ====", tag, NSStringFromClass(c));
    unsigned int n = 0;
    objc_property_t *props = class_copyPropertyList(c, &n);
    for (unsigned int i = 0; i < n; i++) {
        const char *pn = property_getName(props[i]);
        NSString *key = [NSString stringWithUTF8String:pn];
        id val = nil;
        @try { val = [obj valueForKey:key]; } @catch (NSException *e) { val = @"<取不到>"; }
        NSString *desc = @"";
        if ([val isKindOfClass:[NSString class]] || [val isKindOfClass:[NSNumber class]]) {
            desc = [val description];
        } else if ([val isKindOfClass:[NSArray class]]) {
            desc = [NSString stringWithFormat:@"(数组 %lu 项)", (unsigned long)[(NSArray *)val count]];
        } else if (val) {
            desc = NSStringFromClass([val class]);
        }
        if (desc.length > 80) desc = [desc substringToIndex:80];
        L(@"   %-24s = %@", pn, desc);
    }
    free(props);
}

static void DumpClassMethods(Class c, NSString *tag) {
    L(@"---- %@ 方法 ----", tag);
    unsigned int n = 0;
    Method *ms = class_copyMethodList(c, &n);
    for (unsigned int i = 0; i < n; i++) {
        const char *sn = sel_getName(method_getName(ms[i]));
        const char *types = method_getTypeEncoding(ms[i]);
        L(@"   %-46s %s", sn, types ? types : "");
    }
    free(ms);
}

// ---- hooks ----
static void (*orig_showMenu)(id, SEL) = NULL;
static void my_showMenu(id self, SEL _cmd) {
    L(@"### showMenu: 被调用，对象=%@", NSStringFromClass([self class]));
    DumpObject(self, @"WDMenuView 实例");
    Class wd = objc_getClass("WDRow");
    if (wd) { DumpClassMethods(wd, @"WDRow"); }
    if (orig_showMenu) orig_showMenu(self, _cmd);
}

static void (*orig_initRow)(id, SEL, id, id) = NULL;
static void my_initRow(id self, SEL _cmd, id row, id menu) {
    if (orig_initRow) orig_initRow(self, _cmd, row, menu);
    static int cnt = 0;
    if (cnt++ < 40) {
        DumpObject(row, [NSString stringWithFormat:@"WDRow#%d", cnt]);
        id v = nil;
        @try { v = [row valueForKey:@"action"]; } @catch (NSException *e) {}
        if (v) L(@"   action 类型 = %@", NSStringFromClass([v class]));
        id sub = nil;
        @try { sub = [row valueForKey:@"subRows"]; } @catch (NSException *e) {}
        if ([sub isKindOfClass:[NSArray class]]) {
            L(@"   subRows = %lu 项", (unsigned long)[(NSArray *)sub count]);
            for (id s in sub) {
                if ([s respondsToSelector:@selector(valueForKey:)]) {
                    id t = nil; @try { t = [s valueForKey:@"title"]; } @catch (NSException *e) {}
                    L(@"      · %@", t);
                }
            }
        }
    }
}

__attribute__((constructor)) static void probe_init(void) {
    L(@"===== 菜单探针启动 =====");
    Class m = objc_getClass("WDMenuView");
    if (m) {
        DumpClassMethods(m, @"WDMenuView");
        Method s1 = class_getInstanceMethod(m, @selector(showMenu));
        if (s1) { orig_showMenu = (void (*)(id, SEL))method_getImplementation(s1);
                  method_setImplementation(s1, (IMP)my_showMenu); L(@"hook showMenu 成功"); }
        else L(@"showMenu 方法不存在");
    } else L(@"找不到 WDMenuView");
    Class r = objc_getClass("WDRow");
    if (r) {
        DumpClassMethods(r, @"WDRow");
        Method s2 = class_getInstanceMethod(r, @selector(initWithRow:menu:));
        if (s2) { orig_initRow = (void (*)(id, SEL, id, id))method_getImplementation(s2);
                  method_setImplementation(s2, (IMP)my_initRow); L(@"hook initWithRow:menu: 成功"); }
        else L(@"initWithRow:menu: 不存在");
    } else L(@"找不到 WDRow");
    L(@"===== 探针就绪 =====");
}
