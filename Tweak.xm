// Tweak.xm —— Today 自有授权层（零依赖版：只用 ObjC runtime，不需要 Substrate/Orion）
//
// 卡密格式：TODAY-XXXX-XXXX-XXXX
//   = Base32( 2字节到期日(自2020-01-01) + 5字节 HMAC-SHA256 截断 )

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonHMAC.h>
#import <objc/runtime.h>

static NSString *const kSecret = @"TODAY-HMAC-2026-ChAnGeMe-9f3a7c";
static NSString *const kStoreKey = @"_today_lic_v1";
static const int kEpochDay = 18262;
static NSString *const kB32 = @"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#pragma mark - 卡密校验

static NSData *b32decode(NSString *s) {
    NSMutableArray *bits = [NSMutableArray array];
    unichar buf[128];
    NSUInteger n = MIN(s.length, 128);
    [s getCharacters:buf range:NSMakeRange(0, n)];
    for (NSUInteger i = 0; i < n; i++) {
        unichar c = buf[i];
        if (c == '-' || c == ' ') continue;
        NSString *one = [NSString stringWithCharacters:&c length:1];
        NSInteger v = [kB32 rangeOfString:one].location;
        if (v == NSNotFound) return nil;
        for (int b = 4; b >= 0; b--) [bits addObject:@((v >> b) & 1)];
    }
    NSMutableData *out = [NSMutableData data];
    for (NSUInteger i = 0; i + 8 <= bits.count; i += 8) {
        uint8_t byte = 0;
        for (int b = 0; b < 8; b++) byte = (uint8_t)((byte << 1) | [bits[i + b] intValue]);
        [out appendBytes:&byte length:1];
    }
    return out;
}

static NSData *hmac5(NSData *msg) {
    unsigned char mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, kSecret.UTF8String, strlen(kSecret.UTF8String),
           msg.bytes, msg.length, mac);
    return [NSData dataWithBytes:mac length:5];
}

static NSInteger verifyCode(NSString *raw) {
    if (!raw.length) return -1;
    NSString *s = [[raw stringByTrimmingCharactersInSet:
                    [NSCharacterSet whitespaceAndNewlineCharacterSet]] uppercaseString];
    if ([s hasPrefix:@"TODAY"]) s = [s substringFromIndex:5];
    NSData *bin = b32decode(s);
    if (bin.length < 7) return -1;
    NSData *body = [bin subdataWithRange:NSMakeRange(0, 2)];
    NSData *mac = [bin subdataWithRange:NSMakeRange(2, 5)];
    if (![mac isEqualToData:hmac5(body)]) return -1;
    const uint8_t *b = (const uint8_t *)body.bytes;
    NSInteger day = ((NSInteger)b[0] << 8) | b[1];
    NSInteger epochDay = day + kEpochDay;
    NSInteger today = (NSInteger)([[NSDate date] timeIntervalSince1970] / 86400.0);
    return epochDay < today ? -2 : epochDay;
}

static void saveLicense(NSInteger epochDay, NSString *code) {
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    [u setObject:@{@"d": @(epochDay), @"c": code} forKey:kStoreKey];
    [u synchronize];
}

static NSInteger loadLicense(void) {
    NSDictionary *d = [[NSUserDefaults standardUserDefaults] objectForKey:kStoreKey];
    if (![d isKindOfClass:[NSDictionary class]]) return -1;
    NSInteger day = [d[@"d"] integerValue];
    NSInteger today = (NSInteger)([[NSDate date] timeIntervalSince1970] / 86400.0);
    return day < today ? -2 : day;
}

#pragma mark - UI

static UIViewController *topVC(UIWindow *win) {
    UIViewController *vc = win.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

static void askForCode(UIWindow *win);

static void showOK(UIViewController *vc, NSString *t, NSString *m) {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:t message:m
                                                       preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [vc presentViewController:a animated:YES completion:nil];
}

static void askForCode(UIWindow *win) {
    UIViewController *vc = topVC(win);
    if (!vc) return;
    UIAlertController *ac =
        [UIAlertController alertControllerWithTitle:@"激活你的设备"
                                            message:@"请输入卖家给你的卡密"
                                     preferredStyle:UIAlertControllerStyleAlert];
    [ac addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"TODAY-XXXX-XXXX-XXXX";
        tf.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    [ac addAction:[UIAlertAction actionWithTitle:@"验证" style:UIAlertActionStyleDefault
                                        handler:^(UIAlertAction *a) {
        NSString *code = ac.textFields.firstObject.text;
        NSInteger day = verifyCode(code);
        if (day > 0) {
            saveLicense(day, code);
            NSDateFormatter *f = [[NSDateFormatter alloc] init];
            f.dateFormat = @"yyyy-MM-dd";
            NSDate *d = [NSDate dateWithTimeIntervalSince1970:day * 86400.0];
            NSLog(@"[TodayHook] 激活成功 到期 %@", [f stringFromDate:d]);
            showOK(topVC(win), @"激活成功", [NSString stringWithFormat:@"有效期至 %@", [f stringFromDate:d]]);
        } else {
            NSString *msg = (day == -2) ? @"该卡密已过期" : @"卡密无效，请检查是否输错";
            UIAlertController *bad =
                [UIAlertController alertControllerWithTitle:@"验证失败" message:msg
                                             preferredStyle:UIAlertControllerStyleAlert];
            [bad addAction:[UIAlertAction actionWithTitle:@"重试" style:UIAlertActionStyleDefault
                                                  handler:^(UIAlertAction *x) { askForCode(win); }]];
            [bad addAction:[UIAlertAction actionWithTitle:@"退出" style:UIAlertActionStyleCancel
                                                  handler:^(UIAlertAction *x) { exit(0); }]];
            [topVC(win) presentViewController:bad animated:YES completion:nil];
        }
    }]];
    [ac addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel
                                        handler:^(UIAlertAction *a) { exit(0); }]];
    [vc presentViewController:ac animated:YES completion:nil];
}

static void checkLicense(UIWindow *win) {
    NSInteger st = loadLicense();
    if (st == -2) {
        UIViewController *vc = topVC(win);
        if (!vc) return;
        UIAlertController *exp =
            [UIAlertController alertControllerWithTitle:@"授权已到期"
                                                message:@"请联系卖家续费"
                                         preferredStyle:UIAlertControllerStyleAlert];
        [exp addAction:[UIAlertAction actionWithTitle:@"退出" style:UIAlertActionStyleDefault
                                              handler:^(UIAlertAction *a) { exit(0); }]];
        [vc presentViewController:exp animated:YES completion:nil];
        return;
    }
    if (st < 0) askForCode(win);
}

#pragma mark - Hook（纯 runtime，无第三方依赖）

static void (*orig_makeKeyAndVisible)(id, SEL) = NULL;

static void my_makeKeyAndVisible(id self, SEL _cmd) {
    if (orig_makeKeyAndVisible) orig_makeKeyAndVisible(self, _cmd);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        checkLicense((UIWindow *)self);
    });
}

static void hookIfExists(const char *cls, SEL sel, IMP imp) {
    Class c = objc_getClass(cls);
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel);
    if (m) method_setImplementation(m, imp);
}

static void gate_showGate(id self, SEL _cmd, id x) { }
static void gate_noop(id self, SEL _cmd) { }

__attribute__((constructor)) static void todayhook_init(void) {
    Class wc = objc_getClass("UIWindow");
    Method m = wc ? class_getInstanceMethod(wc, @selector(makeKeyAndVisible)) : NULL;
    if (m) {
        orig_makeKeyAndVisible = (void (*)(id, SEL))method_getImplementation(m);
        method_setImplementation(m, (IMP)my_makeKeyAndVisible);
    }
    hookIfExists("XQGate", @selector(showGate:), (IMP)gate_showGate);
    hookIfExists("XQGate", @selector(startHeartbeat), (IMP)gate_noop);
    hookIfExists("XQGate", @selector(doBeat), (IMP)gate_noop);
    NSLog(@"[TodayHook] loaded, window-hook=%d", orig_makeKeyAndVisible != NULL);
}
