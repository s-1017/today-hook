// Tweak.xm —— Today 自有授权层（v3：全屏锁定 + 卡密记忆 + 年月日时分秒）
//
// 卡密：TODAY-XXXX-XXXX-XXXX
//   = Base32( 2字节到期日(自2020-01-01) + 5字节 HMAC-SHA256 截断 )
//
// v3 改动：
//   1) 启动即用独立 UIWindow 全屏锁定，HUD 完全不可见，输完卡密才放行
//   2) 卡密保存在本地，下次启动自动填入，点一下「验证」即可
//   3) 到期时间显示到「年月日时分秒」

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonHMAC.h>
#import <objc/runtime.h>

static NSString *const kSecret = @"TODAY-HMAC-2026-ChAnGeMe-9f3a7c";
static NSString *const kStoreKey = @"_today_lic_v1";
static const int kEpochDay = 18262;          // 2020-01-01 距 1970 的天数
static NSString *const kB32 = @"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static UIWindow *gLockWindow = nil;
static BOOL gInHook = NO;

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

// 返回到期时间戳（秒）；-1 无效，-2 已过期
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
    double expireTs = (double)(day + kEpochDay) * 86400.0 + 86399.0;   // 当日 23:59:59
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

static double savedExpire(void) {
    NSDictionary *d = [[NSUserDefaults standardUserDefaults] objectForKey:kStoreKey];
    if (![d isKindOfClass:[NSDictionary class]]) return 0;
    return [d[@"e"] doubleValue];
}

static NSString *fmtTime(double ts) {
    NSDateFormatter *f = [[NSDateFormatter alloc] init];
    f.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    return [f stringFromDate:[NSDate dateWithTimeIntervalSince1970:ts]];
}

#pragma mark - 锁定界面

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

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, w - 60, 34)];
    title.center = CGPointMake(w / 2, self.view.bounds.size.height * 0.30);
    title.text = @"安全模块加载中…";
    title.textColor = [UIColor whiteColor];
    title.font = [UIFont boldSystemFontOfSize:22];
    title.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:title];

    UILabel *sub = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, w - 60, 20)];
    sub.center = CGPointMake(w / 2, title.center.y + 34);
    sub.text = @"请输入卖家给你的卡密后继续";
    sub.textColor = [UIColor colorWithWhite:0.65 alpha:1];
    sub.font = [UIFont systemFontOfSize:14];
    sub.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:sub];

    CGFloat fw = w - 80;
    _field = [[UITextField alloc] initWithFrame:CGRectMake(40, sub.center.y + 40, fw, 46)];
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
    _field.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 12, 1)];
    _field.leftViewMode = UITextFieldViewModeAlways;
    [self.view addSubview:_field];

    // 本地已保存的卡密 → 自动填入
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

    _status = [[UILabel alloc] initWithFrame:CGRectMake(0, _btn.frame.origin.y + 66, w - 60, 44)];
    _status.center = CGPointMake(w / 2, _status.center.y);
    _status.numberOfLines = 0;
    _status.textColor = [UIColor colorWithWhite:0.6 alpha:1];
    _status.font = [UIFont systemFontOfSize:13];
    _status.textAlignment = NSTextAlignmentCenter;
    _status.text = saved.length ? @"已读取上次的卡密，点击「验证」进入" : @"";
    [self.view addSubview:_status];

    UILabel *tip = [[UILabel alloc] initWithFrame:CGRectMake(0, self.view.bounds.size.height - 60, w, 20)];
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
    NSString *code = _field.text;
    double ts = verifyCode(code);
    if (ts > 0) {
        saveLicense([[code stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]] uppercaseString], ts);
        _status.textColor = [UIColor colorWithRed:0.24 green:0.78 blue:0.42 alpha:1];
        _status.text = [NSString stringWithFormat:@"验证通过\n有效期至 %@", fmtTime(ts)];
        [_btn setTitle:@"进入" forState:UIControlStateNormal];
        [_btn removeTarget:self action:@selector(doVerify) forControlEvents:UIControlEventTouchUpInside];
        [_btn addTarget:self action:@selector(unlock) forControlEvents:UIControlEventTouchUpInside];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self unlock]; });
    } else {
        _status.textColor = [UIColor colorWithRed:0.95 green:0.35 blue:0.35 alpha:1];
        _status.text = (ts == -2) ? @"该卡密已过期，请联系卖家续费"
                                  : @"卡密无效，请检查是否输错";
    }
}

- (void)unlock {
    if (gLockWindow) {
        gInHook = YES;
        gLockWindow.hidden = YES;
        gLockWindow = nil;
        gInHook = NO;
        for (UIWindow *w in [[UIApplication sharedApplication] windows]) {
            if (w != gLockWindow && w.rootViewController) { [w makeKeyAndVisible]; break; }
        }
    }
}

@end

#pragma mark - Hook

static void (*orig_makeKeyAndVisible)(id, SEL) = NULL;

static BOOL alreadyValid(void) {
    NSString *c = savedCode();
    if (!c.length) return NO;
    double ts = verifyCode(c);
    if (ts > 0) { saveLicense(c, ts); return YES; }
    return NO;
}

static UIWindow *gAppWindow = nil;

static void my_makeKeyAndVisible(id self, SEL _cmd) {
    if (orig_makeKeyAndVisible) orig_makeKeyAndVisible(self, _cmd);
    if (gInHook) return;
    if (gLockWindow) return;                 // 已经上锁，不重复
    gAppWindow = (UIWindow *)self;

    // 每次启动都要过验证页（卡密会自动填入，点一下「验证」即可）
    (void)alreadyValid;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (gLockWindow) return;
        gInHook = YES;
        UIWindow *w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        w.windowLevel = UIWindowLevelAlert + 100;
        w.backgroundColor = [UIColor blackColor];
        w.rootViewController = [[LCLockVC alloc] init];
        w.hidden = NO;
        [w makeKeyAndVisible];
        gLockWindow = w;
        gInHook = NO;
        NSLog(@"[TodayHook] 锁屏已显示");
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
    NSLog(@"[TodayHook] v3 loaded");
}
