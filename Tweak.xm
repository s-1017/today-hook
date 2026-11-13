// Tweak.xm —— Today 自有授权层 v7（在线校验 + 离线兜底 + 远程作废）
//
// 流程：
//   启动/验证 → 请求 https://服务器/api/v1/activate?code=&device=
//     · 服务器可达且 ok      → 用服务器返回的到期时间放行
//     · 服务器可达但被拒      → 显示服务器原因（已作废/已过期/不存在），不放行
//     · 服务器不可达          → 离线兜底：本地 HMAC 校验（有效则放行，记录"离线"）
//   运行中每 30 分钟心跳；服务器说失效 → 立刻清本地并重新锁屏

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonHMAC.h>
#import <objc/runtime.h>

static NSString *const kSecret = @"TODAY-HMAC-2026-ChAnGeMe-9f3a7c";
static NSString *const kStoreKey = @"_today_lic_v1";
static NSString *const kDevKey = @"_today_dev_id";
static NSString *const kAPIBase = @"https://134.175.44.168/api/v1";
static const int kEpochDay = 18262;
static NSString *const kB32 = @"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static UIWindow *gAppWindow = nil;
static NSTimer *gGuard = nil;
static NSTimer *gBeat = nil;
static BOOL gInHook = NO;
static BOOL gUnlocked = NO;
@class LCLockVC;
static LCLockVC *gLockVC = nil;

#define LC_BLUE [UIColor colorWithRed:0.18 green:0.48 blue:0.96 alpha:1.0]
#define LC_BG   [UIColor colorWithRed:0.043 green:0.051 blue:0.071 alpha:1.0]
#define LC_CARD [UIColor colorWithRed:0.055 green:0.067 blue:0.090 alpha:1.0]
#define LC_BORD [UIColor colorWithRed:0.129 green:0.161 blue:0.212 alpha:1.0]
#define LC_FIELD [UIColor colorWithRed:0.051 green:0.067 blue:0.090 alpha:1.0]

#pragma mark - Base32 / HMAC（离线兜底）

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

// 返回天数（>0 有效）；-1 格式/签名错误
static NSInteger verifyCodeDays(NSString *raw) {
    if (!raw.length) return -1;
    NSString *s = [[raw stringByTrimmingCharactersInSet:
                    [NSCharacterSet whitespaceAndNewlineCharacterSet]] uppercaseString];
    if ([s hasPrefix:@"TODAY"]) s = [s substringFromIndex:5];
    NSData *bin = b32decode(s);
    if (bin.length < 9) return -1;
    NSData *body = [bin subdataWithRange:NSMakeRange(0, 4)];
    NSData *mac = [bin subdataWithRange:NSMakeRange(4, 5)];
    if (![mac isEqualToData:hmac5(body)]) return -1;
    const uint8_t *b = (const uint8_t *)body.bytes;
    NSInteger days = ((NSInteger)b[0] << 8) | b[1];
    return days > 0 ? days : -1;
}

#pragma mark - 本地存储

static void saveLicenseEx(NSString *code, double expireTs, double activatedTs);

static void saveLicense(NSString *code, double expireTs) {
    saveLicenseEx(code, expireTs, [[NSDate date] timeIntervalSince1970]);
}

static void saveLicenseEx(NSString *code, double expireTs, double activatedTs) {
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    [u setObject:@{@"c": code ?: @"", @"e": @(expireTs), @"a": @(activatedTs),
                   @"t": @([[NSDate date] timeIntervalSince1970])} forKey:kStoreKey];
    [u synchronize];
}

static NSString *savedCode(void) {
    NSDictionary *d = [[NSUserDefaults standardUserDefaults] objectForKey:kStoreKey];
    if (![d isKindOfClass:[NSDictionary class]]) return nil;
    NSString *c = d[@"c"];
    return [c isKindOfClass:[NSString class]] ? c : nil;
}

static void clearLicense(void) {
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    [u removeObjectForKey:kStoreKey];
    [u synchronize];
}

static NSString *deviceId(void) {
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    NSString *d = [u objectForKey:kDevKey];
    if (![d isKindOfClass:[NSString class]] || d.length < 6) {
        d = [[NSUUID UUID] UUIDString];
        [u setObject:d forKey:kDevKey];
        [u synchronize];
    }
    return d;
}

static NSString *fmtTime(double ts) {
    NSDateFormatter *f = [[NSDateFormatter alloc] init];
    f.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    return [f stringFromDate:[NSDate dateWithTimeIntervalSince1970:ts]];
}

#pragma mark - 网络（自签证书放行）

@interface LCNet : NSObject <NSURLSessionDelegate>
+ (void)request:(NSString *)path
           code:(NSString *)code
           done:(void (^)(BOOL reachable, BOOL ok, double exp, NSString *msg))done;
@end

@implementation LCNet
+ (void)URLSession:(NSURLSession *)s didReceiveChallenge:(NSURLAuthenticationChallenge *)ch
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))c {
    if ([ch.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        c(NSURLSessionAuthChallengeUseCredential,
          [NSURLCredential credentialForTrust:ch.protectionSpace.serverTrust]);
    } else {
        c(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

+ (void)request:(NSString *)path
           code:(NSString *)code
           done:(void (^)(BOOL, BOOL, double, NSString *))done {
    NSString *urlStr = [NSString stringWithFormat:@"%@/%@?code=%@&device=%@",
                        kAPIBase, path,
                        [code stringByAddingPercentEncodingWithAllowedCharacters:
                         [NSCharacterSet URLQueryAllowedCharacterSet]],
                        [deviceId() stringByAddingPercentEncodingWithAllowedCharacters:
                         [NSCharacterSet URLQueryAllowedCharacterSet]]];
    NSURL *url = [NSURL URLWithString:urlStr];
    if (!url) { done(NO, NO, 0, @"URL 构造失败"); return; }

    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cfg.timeoutIntervalForRequest = 6;
    cfg.timeoutIntervalForResource = 8;
    NSURLSession *sess = [NSURLSession sessionWithConfiguration:cfg delegate:(id<NSURLSessionDelegate>)self
                                                  delegateQueue:nil];
    [[sess dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (err || !data.length) { done(NO, NO, 0, @"网络不可达"); return; }
            NSDictionary *j = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (![j isKindOfClass:[NSDictionary class]]) { done(YES, NO, 0, @"服务器响应异常"); return; }
            BOOL ok = [j[@"ok"] boolValue];
            double exp = [j[@"expire_at"] doubleValue];
            NSString *msg = [j[@"msg"] isKindOfClass:[NSString class]] ? j[@"msg"] : @"";
            done(YES, ok, exp, msg);
        });
    }] resume];
    [sess finishTasksAndInvalidate];
}
@end

#pragma mark - 激活界面

static void LCUnlock(void);
static void LCForceLock(NSString *reason);

@interface LCLockVC : UIViewController <UITextFieldDelegate>
@property (nonatomic, strong) UITextField *field;
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) UIButton *btn;
@property (nonatomic, strong) UIView *card;
@end

@implementation LCLockVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = LC_BG;

    CGFloat w = self.view.bounds.size.width;
    CGFloat h = self.view.bounds.size.height;

    CGFloat iconS = 82;
    UIView *icon = [[UIView alloc] initWithFrame:CGRectMake((w - iconS) / 2, h * 0.085, iconS, iconS)];
    icon.backgroundColor = LC_BLUE;
    icon.layer.cornerRadius = 19;
    icon.layer.shadowColor = LC_BLUE.CGColor;
    icon.layer.shadowOpacity = 0.55;
    icon.layer.shadowRadius = 18;
    icon.layer.shadowOffset = CGSizeZero;
    [self.view addSubview:icon];
    UILabel *ic = [[UILabel alloc] initWithFrame:icon.bounds];
    ic.text = @"T";
    ic.textColor = [UIColor whiteColor];
    ic.font = [UIFont boldSystemFontOfSize:46];
    ic.textAlignment = NSTextAlignmentCenter;
    [icon addSubview:ic];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(0, icon.frame.origin.y + iconS + 16, w, 42)];
    title.text = @"Today内部版";
    title.textColor = [UIColor whiteColor];
    title.font = [UIFont boldSystemFontOfSize:32];
    title.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:title];

    CGFloat cardW = w - 56, cardH = 208, cardY = h * 0.455;
    _card = [[UIView alloc] initWithFrame:CGRectMake(28, cardY, cardW, cardH)];
    _card.backgroundColor = LC_CARD;
    _card.layer.cornerRadius = 16;
    _card.layer.borderWidth = 1;
    _card.layer.borderColor = LC_BORD.CGColor;
    [self.view addSubview:_card];

    UILabel *lab = [[UILabel alloc] initWithFrame:CGRectMake(18, 16, cardW - 36, 18)];
    lab.text = @"卡密激活";
    lab.textColor = LC_BLUE;
    lab.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    [_card addSubview:lab];

    _field = [[UITextField alloc] initWithFrame:CGRectMake(10, 40, cardW - 20, 54)];
    _field.backgroundColor = LC_FIELD;
    _field.layer.cornerRadius = 10;
    _field.layer.borderWidth = 1;
    _field.layer.borderColor = LC_BORD.CGColor;
    _field.textColor = [UIColor whiteColor];
    _field.tintColor = LC_BLUE;
    _field.font = [UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightRegular];
    _field.placeholder = @"请输入卡密";
    _field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    _field.autocorrectionType = UITextAutocorrectionTypeNo;
    _field.returnKeyType = UIReturnKeyDone;
    _field.delegate = self;
    _field.clearButtonMode = UITextFieldViewModeWhileEditing;
    _field.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 14, 1)];
    _field.leftViewMode = UITextFieldViewModeAlways;
    [_card addSubview:_field];

    NSString *saved = savedCode();
    if (saved.length) _field.text = saved;

    _btn = [UIButton buttonWithType:UIButtonTypeSystem];
    _btn.frame = CGRectMake(10, 108, cardW - 20, 54);
    _btn.backgroundColor = LC_BLUE;
    _btn.layer.cornerRadius = 12;
    [_btn setTitle:@"验 证 激 活" forState:UIControlStateNormal];
    [_btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    _btn.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    [_btn addTarget:self action:@selector(doVerify) forControlEvents:UIControlEventTouchUpInside];
    [_card addSubview:_btn];

    _status = [[UILabel alloc] initWithFrame:CGRectMake(16, 172, cardW - 32, 22)];
    _status.textColor = [UIColor colorWithWhite:0.55 alpha:1];
    _status.font = [UIFont systemFontOfSize:12];
    _status.textAlignment = NSTextAlignmentCenter;
    _status.text = saved.length ? @"已加载卡密，请登录" : @"";
    [_card addSubview:_status];

    UIButton *clear = [UIButton buttonWithType:UIButtonTypeSystem];
    clear.frame = CGRectMake(0, h - 92, w, 40);
    [clear setTitle:@"清除已保存的卡密" forState:UIControlStateNormal];
    [clear setTitleColor:[UIColor colorWithWhite:0.40 alpha:1] forState:UIControlStateNormal];
    clear.titleLabel.font = [UIFont systemFontOfSize:12];
    [clear addTarget:self action:@selector(doClear) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:clear];
}

- (void)doClear {
    clearLicense();
    _field.text = @"";
    _status.textColor = [UIColor colorWithWhite:0.55 alpha:1];
    _status.text = @"已清除本地卡密";
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
    if (!code.length) {
        _status.textColor = [UIColor colorWithRed:0.95 green:0.35 blue:0.35 alpha:1];
        _status.text = @"请先输入卡密";
        return;
    }
    _btn.enabled = NO;
    [_btn setTitle:@"验 证 中…" forState:UIControlStateNormal];
    _status.textColor = [UIColor colorWithWhite:0.55 alpha:1];
    _status.text = @"正在联网验证…";

    [LCNet request:@"activate" code:code done:^(BOOL reachable, BOOL ok, double exp, NSString *msg) {
        self->_btn.enabled = YES;
        [self->_btn setTitle:@"验 证 激 活" forState:UIControlStateNormal];

        if (reachable && ok && exp > 0) {
            saveLicense(code, exp);
            self->_status.textColor = [UIColor colorWithRed:0.24 green:0.78 blue:0.42 alpha:1];
            self->_status.text = [NSString stringWithFormat:@"验证通过 · 有效期至 %@", fmtTime(exp)];
            [self->_btn setTitle:@"进 入 中…" forState:UIControlStateNormal];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ LCUnlock(); });
            return;
        }
        if (reachable && !ok) {
            self->_status.textColor = [UIColor colorWithRed:0.95 green:0.35 blue:0.35 alpha:1];
            self->_status.text = msg.length ? msg : @"验证失败";
            return;
        }
        // 网络不可达 → 离线兜底（同样是"首次激活起算"）
        NSInteger days = verifyCodeDays(code);
        if (days > 0) {
            double act = [[NSDate date] timeIntervalSince1970];
            NSDictionary *old = [[NSUserDefaults standardUserDefaults] objectForKey:kStoreKey];
            if ([old isKindOfClass:[NSDictionary class]] &&
                [old[@"c"] isEqualToString:code] && [old[@"a"] doubleValue] > 0) {
                act = [old[@"a"] doubleValue];      // 同一张卡沿用首次激活时间
            }
            double exp = act + days * 86400.0;
            saveLicenseEx(code, exp, act);
            self->_status.textColor = [UIColor colorWithRed:0.95 green:0.72 blue:0.24 alpha:1];
            self->_status.text = [NSString stringWithFormat:@"离线验证通过 · 有效期至 %@", fmtTime(exp)];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ LCUnlock(); });
        } else {
            self->_status.textColor = [UIColor colorWithRed:0.95 green:0.35 blue:0.35 alpha:1];
            self->_status.text = @"网络不可用，且卡密格式无效";
        }
    }];
}

@end

#pragma mark - 锁定控制

static void LCShowLock(void);

static void LCStartBeat(void) {
    if (gBeat) [gBeat invalidate];
    gBeat = [NSTimer scheduledTimerWithTimeInterval:1800 repeats:YES block:^(NSTimer *t) {
        NSString *c = savedCode();
        if (!c.length) return;
        [LCNet request:@"heartbeat" code:c done:^(BOOL reachable, BOOL ok, double exp, NSString *msg) {
            if (!reachable) return;                 // 离线：放行，等下次
            if (ok && exp > 0) { saveLicense(c, exp); return; }
            NSLog(@"[TodayHook] 服务器判定失效: %@", msg);
            clearLicense();
            LCForceLock(msg.length ? msg : @"授权已失效");
        }];
    }];
}

static void LCUnlock(void) {
    if (gUnlocked) return;
    gUnlocked = YES;
    if (gGuard) { [gGuard invalidate]; gGuard = nil; }
    gInHook = YES;
    LCLockVC *vc = gLockVC;
    gLockVC = nil;
    if (vc) [vc dismissViewControllerAnimated:NO completion:nil];
    if (gAppWindow) [gAppWindow makeKeyAndVisible];
    gInHook = NO;
    LCStartBeat();
    NSLog(@"[TodayHook] 已解锁");
}

static void LCForceLock(NSString *reason) {
    gUnlocked = NO;
    if (gBeat) { [gBeat invalidate]; gBeat = nil; }
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gLockVC) LCShowLock();
        if (gLockVC) {
            gLockVC.status.textColor = [UIColor colorWithRed:0.95 green:0.35 blue:0.35 alpha:1];
            gLockVC.status.text = reason;
            gLockVC.field.text = @"";
        }
    });
}

static void LCGuardTick(void) {
    if (gUnlocked) {
        if (gGuard) { [gGuard invalidate]; gGuard = nil; }
        return;
    }
    if (!gLockVC || !gLockVC.view.window) LCShowLock();
}

static void LCStartGuard(void) {
    if (gGuard) return;
    gGuard = [NSTimer scheduledTimerWithTimeInterval:0.4 repeats:YES block:^(NSTimer *t) {
        LCGuardTick();
    }];
}

static void LCShowLock(void) {
    if (gUnlocked) return;
    if (gLockVC && gLockVC.view.window) return;

    UIViewController *host = gAppWindow.rootViewController;
    if (!host) {
        for (UIWindow *w in [[UIApplication sharedApplication] windows]) {
            if (w.rootViewController) { host = w.rootViewController; break; }
        }
    }
    if (!host) return;
    while (host.presentedViewController &&
           ![host.presentedViewController isKindOfClass:[LCLockVC class]]) {
        host = host.presentedViewController;
    }

    gInHook = YES;
    LCLockVC *vc = [[LCLockVC alloc] init];
    vc.modalPresentationStyle = UIModalPresentationFullScreen;
    gLockVC = vc;
    [host presentViewController:vc animated:NO completion:nil];
    gInHook = NO;
    LCStartGuard();
}

#pragma mark - Hook

static void (*orig_makeKeyAndVisible)(id, SEL) = NULL;

static void my_makeKeyAndVisible(id self, SEL _cmd) {
    if (orig_makeKeyAndVisible) orig_makeKeyAndVisible(self, _cmd);
    if (gUnlocked) return;
    if (gInHook) return;
    if (gLockVC) return;
    gAppWindow = (UIWindow *)self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (gUnlocked || gLockVC) return;
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
    NSLog(@"[TodayHook] v7 loaded");
}
