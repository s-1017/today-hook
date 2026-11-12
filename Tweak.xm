// Tweak.xm —— Today 自有授权层 v4
//   · 全屏锁定 + 看门狗（锁屏被 App 关掉会自动重新盖回）
//   · 未验证时禁用底层窗口触摸
//   · 卡密本地保存、下次自动填入
//   · 到期时间显示到年月日时分秒

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonHMAC.h>
#import <objc/runtime.h>

static NSString *const kSecret = @"TODAY-HMAC-2026-ChAnGeMe-9f3a7c";
static NSString *const kStoreKey = @"_today_lic_v1";
static const int kEpochDay = 18262;
static NSString *const kB32 = @"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static UIWindow *gLockWindow = nil;
static UIWindow *gAppWindow = nil;
static NSTimer *gGuard = nil;
static BOOL gInHook = NO;
static BOOL gUnlocked = NO;

#pragma mark - Base32 / HMAC

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

static double verifyCode(NSString *raw) {
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
    double expireTs = (double)(day + kEpochDay) * 86400.0 + 86399.0;
    if (expireTs < [[NSDate date] timeIntervalSince1970]) return -2;
    return expireTs;
}

#pragma mark - 本地保存

static void saveLicense(NSString *code, double expireTs) {
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    [u setObject:@{@"c": code ?: @"", @"e": @(expireTs)} forKey:kStoreKey];
    [u synchronize];
}

static NSString *savedCode(void) {
    NSDictionary *d = [[NSUserDefaults standardUserDefaults] objectForKey:kStoreKey];
    if (![d isKindOfClass:[NSDictionary class]]) return nil;
    NSString *c = d[@"c"];
    return [c isKindOfClass:[NSString class]] ? c : nil;
}

static NSString *fmtTime(double ts) {
    NSDateFormatter *f = [[NSDateFormatter alloc] init];
    f.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    return [f stringFromDate:[NSDate dateWithTimeIntervalSince1970:ts]];
}

#pragma mark - 锁定界面

static void LCUnlock(void);

@interface LCLockVC : UIViewController <UITextFieldDelegate>
@property (nonatomic, strong) UITextField *field;
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) UIButton *btn;
@end

@implementation LCLockVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.04 green:0.05 blue:0.07 alpha:1.0];

    CGFloat w = self.view.bounds.size.width;
    CGFloat h = self.view.bounds.size.height;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, w - 60, 40)];
    title.center = CGPointMake(w / 2, h * 0.32);
    title.text = @"Today-内部版";
    title.textColor = [UIColor whiteColor];
    title.font = [UIFont boldSystemFontOfSize:28];
    title.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:title];

    CGFloat fw = w - 80;
    _field = [[UITextField alloc] initWithFrame:CGRectMake(40, title.center.y + 56, fw, 46)];
    _field.backgroundColor = [UIColor colorWithWhite:0.11 alpha:1];
    _field.layer.cornerRadius = 10;
    _field.layer.borderWidth = 1;
    _field.layer.borderColor = [UIColor colorWithWhite:0.25 alpha:1].CGColor;
    _field.textColor = [UIColor whiteColor];
    _field.tintColor = [UIColor whiteColor];
    _field.font = [UIFont monospacedSystemFontOfSize:16 weight:UIFontWeightMedium];
    _field.textAlignment = NSTextAlignmentCenter;
    _field.placeholder = @"TODAY-XXXX-XXXX-XXXX";
    _field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    _field.autocorrectionType = UITextAutocorrectionTypeNo;
    _field.returnKeyType = UIReturnKeyDone;
    _field.delegate = self;
    [self.view addSubview:_field];

    NSString *saved = savedCode();
    if (saved.length) _field.text = saved;

    _btn = [UIButton buttonWithType:UIButtonTypeSystem];
    _btn.frame = CGRectMake(40, _field.frame.origin.y + 62, fw, 48);
    _btn.backgroundColor = [UIColor colorWithRed:0.20 green:0.53 blue:0.98 alpha:1];
    _btn.layer.cornerRadius = 10;
    [_btn setTitle:@"验 证" forState:UIControlStateNormal];
    [_btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    _btn.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    [_btn addTarget:self action:@selector(doVerify) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_btn];

    _status = [[UILabel alloc] initWithFrame:CGRectMake(24, _btn.frame.origin.y + 66, w - 48, 48)];
    _status.numberOfLines = 0;
    _status.textColor = [UIColor colorWithWhite:0.6 alpha:1];
    _status.font = [UIFont systemFontOfSize:13];
    _status.textAlignment = NSTextAlignmentCenter;
    _status.text = saved.length ? @"已读取上次的卡密，点击「验证」进入" : @"";
    [self.view addSubview:_status];

    UILabel *tip = [[UILabel alloc] initWithFrame:CGRectMake(0, h - 60, w, 20)];
    tip.text = @"授权有效期以卡密为准";
    tip.textColor = [UIColor colorWithWhite:0.35 alpha:1];
    tip.font = [UIFont systemFontOfSize:11];
    tip.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:tip];
}

- (BOOL)textFieldShouldReturn:(UITextField *)tf {
    [tf resignFirstResponder];
    [self doVerify];
    return YES;
}

- (void)doVerify {
    [_field resignFirstResponder];
    NSString *code = [[_field.text stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]] uppercaseString];
    double ts = verifyCode(code);
    if (ts > 0) {
        saveLicense(code, ts);
        _status.textColor = [UIColor colorWithRed:0.24 green:0.78 blue:0.42 alpha:1];
        _status.text = [NSString stringWithFormat:@"验证通过\n有效期至 %@", fmtTime(ts)];
        _btn.enabled = NO;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.7 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self unlock]; });
    } else {
        _status.textColor = [UIColor colorWithRed:0.95 green:0.35 blue:0.35 alpha:1];
        _status.text = (ts == -2) ? @"该卡密已过期，请联系卖家续费"
                                  : @"卡密无效，请检查是否输错";
    }
}

- (void)unlock {
    LCUnlock();
}

@end

#pragma mark - 看门狗 / 锁定控制

static void LCShowLock(void);

static void LCUnlock(void) {
    if (gUnlocked) return;
    gUnlocked = YES;
    if (gGuard) { [gGuard invalidate]; gGuard = nil; }
    gInHook = YES;
    UIWindow *w = gLockWindow;
    gLockWindow = nil;
    if (w) {
        [w.rootViewController dismissViewControllerAnimated:NO completion:nil];
        w.rootViewController = nil;
        w.hidden = YES;
    }
    for (UIWindow *win in [[UIApplication sharedApplication] windows]) {
        win.userInteractionEnabled = YES;
        if (win != w && win.rootViewController) { [win makeKeyAndVisible]; break; }
    }
    gInHook = NO;
    NSLog(@"[TodayHook] 已解锁");
}

static void LCGuardTick(void) {
    if (gUnlocked) {
        if (gGuard) { [gGuard invalidate]; gGuard = nil; }
        return;
    }
    if (!gLockWindow) { LCShowLock(); return; }

    // 锁屏被隐藏 / 被夺走 key → 抢回来
    if (gLockWindow.hidden) gLockWindow.hidden = NO;
    if (![gLockWindow isKeyWindow]) {
        gInHook = YES;
        [gLockWindow makeKeyAndVisible];
        gInHook = NO;
    }
    // 未验证时禁止操作底层窗口
    for (UIWindow *win in [[UIApplication sharedApplication] windows]) {
        if (win != gLockWindow) win.userInteractionEnabled = NO;
    }
}

static void LCStartGuard(void) {
    if (gGuard) return;
    gGuard = [NSTimer scheduledTimerWithTimeInterval:0.4 repeats:YES block:^(NSTimer *t) {
        LCGuardTick();
    }];
}

static void LCShowLock(void) {
    if (gUnlocked || gLockWindow) return;
    gInHook = YES;
    UIWindow *w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    w.windowLevel = UIWindowLevelAlert + 10000;
    w.backgroundColor = [UIColor blackColor];
    w.rootViewController = [[LCLockVC alloc] init];
    w.hidden = NO;
    gLockWindow = w;
    [w makeKeyAndVisible];
    gInHook = NO;
    LCStartGuard();
    NSLog(@"[TodayHook] 锁屏已显示 (level=%d)", (int)w.windowLevel);
}

#pragma mark - Hook

static void (*orig_makeKeyAndVisible)(id, SEL) = NULL;

static void my_makeKeyAndVisible(id self, SEL _cmd) {
    if (orig_makeKeyAndVisible) orig_makeKeyAndVisible(self, _cmd);
    if (gUnlocked) return;
    if (gInHook) return;
    if (gLockWindow) return;
    if (self == gLockWindow) return;
    gAppWindow = (UIWindow *)self;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (gUnlocked || gLockWindow) return;
        LCShowLock();
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
    NSLog(@"[TodayHook] v4 loaded");
}
