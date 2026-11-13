// Tweak.xm —— Today 授权层 v9（场景级独立窗口，零闪烁）
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonHMAC.h>
#import <objc/runtime.h>
#import <Security/Security.h>

static NSString *const kSecret = @"TODAY-HMAC-2026-ChAnGeMe-9f3a7c";
static NSString *const kStoreKey = @"_today_lic_v1";
static NSString *const kTypedKey = @"_today_typed";
static NSString *const kDevKey = @"_today_dev_id";
static NSString *const kAPIBase = @"https://134.175.44.168/api/v1";
static NSString *const kB32 = @"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static UIWindow *gLockWin = nil;
static UIWindow *gAppWin = nil;
static NSTimer *gGuard = nil;
static NSTimer *gBeat = nil;
static BOOL gUnlocked = NO;

#define LC_BLUE [UIColor colorWithRed:0.18 green:0.48 blue:0.96 alpha:1.0]
#define LC_BG   [UIColor colorWithRed:0.043 green:0.051 blue:0.071 alpha:1.0]
#define LC_CARD [UIColor colorWithRed:0.055 green:0.067 blue:0.090 alpha:1.0]
#define LC_BORD [UIColor colorWithRed:0.129 green:0.161 blue:0.212 alpha:1.0]
#define LC_FIELD [UIColor colorWithRed:0.051 green:0.067 blue:0.090 alpha:1.0]

#pragma mark - 卡密校验（离线兜底）

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

static NSInteger verifyDays(NSString *raw) {
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

#pragma mark - 存储

static NSString *deviceId(void);
static void stampOnline(NSString *code);
static BOOL offlineAllowed(NSString *code);

static void saveLicense(NSString *code, double exp) {
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    NSDictionary *old = [u objectForKey:kStoreKey];
    if ([old isKindOfClass:[NSDictionary class]]) [d addEntriesFromDictionary:old];
    d[@"c"] = code ?: @"";
    d[@"e"] = @(exp);
    [u setObject:d forKey:kStoreKey];
    [u synchronize];
}

static void stampOnline(NSString *code) {
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    NSDictionary *old = [u objectForKey:kStoreKey];
    if ([old isKindOfClass:[NSDictionary class]]) [d addEntriesFromDictionary:old];
    d[@"o"] = @([[NSDate date] timeIntervalSince1970]);
    d[@"dv"] = deviceId();
    d[@"c"] = code ?: @"";
    [u setObject:d forKey:kStoreKey];
    [u synchronize];
}

static BOOL offlineAllowed(NSString *code) {
    NSDictionary *d = [[NSUserDefaults standardUserDefaults] objectForKey:kStoreKey];
    if (![d isKindOfClass:[NSDictionary class]]) return NO;
    NSString *c = d[@"c"], *dv = d[@"dv"];
    if (![c isKindOfClass:[NSString class]] || ![c isEqualToString:code]) return NO;
    if (![dv isKindOfClass:[NSString class]] || ![dv isEqualToString:deviceId()]) return NO;
    double o = [d[@"o"] doubleValue];
    return o > 0 && ([[NSDate date] timeIntervalSince1970] - o) < 24 * 3600;
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
    [u removeObjectForKey:kTypedKey];
    [u synchronize];
}

static NSString *kcGet(void) {
    NSDictionary *q = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                        (__bridge id)kSecAttrService: @"com.today.internal.lic",
                        (__bridge id)kSecAttrAccount: @"devid",
                        (__bridge id)kSecReturnData: @YES,
                        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne};
    CFTypeRef r = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &r) == errSecSuccess && r) {
        NSData *d = (__bridge_transfer NSData *)r;
        NSString *v = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if ([v isKindOfClass:[NSString class]] && v.length >= 6) return v;
    }
    return nil;
}

static void kcSet(NSString *v) {
    NSDictionary *base = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                           (__bridge id)kSecAttrService: @"com.today.internal.lic",
                           (__bridge id)kSecAttrAccount: @"devid"};
    SecItemDelete((__bridge CFDictionaryRef)base);
    NSMutableDictionary *add = [base mutableCopy];
    add[(__bridge id)kSecValueData] = [v dataUsingEncoding:NSUTF8StringEncoding];
    add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    SecItemAdd((__bridge CFDictionaryRef)add, NULL);
}

static NSString *deviceId(void) {
    NSString *v = kcGet();
    if (v.length) return v;
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    NSString *d = [u objectForKey:kDevKey];
    if (![d isKindOfClass:[NSString class]] || d.length < 6) {
        d = [[NSUUID UUID] UUIDString];
        [u setObject:d forKey:kDevKey];
        [u synchronize];
    }
    kcSet(d);
    return d;
}

static NSString *fmtTime(double ts) {
    NSDateFormatter *f = [[NSDateFormatter alloc] init];
    f.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    return [f stringFromDate:[NSDate dateWithTimeIntervalSince1970:ts]];
}

#pragma mark - 网络

@interface LCNet : NSObject <NSURLSessionDelegate>
+ (void)request:(NSString *)path code:(NSString *)code
           done:(void (^)(BOOL reachable, BOOL ok, double exp, NSString *msg))done;
@end

@implementation LCNet
+ (void)URLSession:(NSURLSession *)s didReceiveChallenge:(NSURLAuthenticationChallenge *)ch
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))c {
    if ([ch.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
        c(NSURLSessionAuthChallengeUseCredential,
          [NSURLCredential credentialForTrust:ch.protectionSpace.serverTrust]);
    else
        c(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

+ (void)request:(NSString *)path code:(NSString *)code
           done:(void (^)(BOOL, BOOL, double, NSString *))done {
    NSString *u = [NSString stringWithFormat:@"%@/%@?code=%@&device=%@", kAPIBase, path,
                   [code stringByAddingPercentEncodingWithAllowedCharacters:
                    [NSCharacterSet URLQueryAllowedCharacterSet]],
                   [deviceId() stringByAddingPercentEncodingWithAllowedCharacters:
                    [NSCharacterSet URLQueryAllowedCharacterSet]]];
    NSURL *url = [NSURL URLWithString:u];
    if (!url) { done(NO, NO, 0, @"URL 错误"); return; }
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cfg.timeoutIntervalForRequest = 6;
    NSURLSession *ss = [NSURLSession sessionWithConfiguration:cfg
                                                     delegate:(id<NSURLSessionDelegate>)self
                                                delegateQueue:nil];
    [[ss dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *r, NSError *e) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (e || !data.length) { done(NO, NO, 0, @"网络不可达"); return; }
            NSDictionary *j = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (![j isKindOfClass:[NSDictionary class]]) { done(YES, NO, 0, @"响应异常"); return; }
            done(YES, [j[@"ok"] boolValue], [j[@"expire_at"] doubleValue],
                 [j[@"msg"] isKindOfClass:[NSString class]] ? j[@"msg"] : @"");
        });
    }] resume];
    [ss finishTasksAndInvalidate];
}
@end

#pragma mark - 验证界面

static void LCUnlock(void);
static void LCInstallLock(void);

@interface LCLockVC : UIViewController <UITextFieldDelegate>
@property (nonatomic, strong) UITextField *field;
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) UIButton *btn;
@end

@implementation LCLockVC

- (void)loadView {
    UIView *v = [[UIView alloc] initWithFrame:[UIScreen mainScreen].bounds];
    v.backgroundColor = LC_BG;
    self.view = v;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    CGFloat w = self.view.bounds.size.width, h = self.view.bounds.size.height;

    UIView *icon = [[UIView alloc] initWithFrame:CGRectMake((w - 82) / 2, h * 0.085, 82, 82)];
    icon.backgroundColor = LC_BLUE;
    icon.layer.cornerRadius = 19;
    icon.layer.shadowColor = LC_BLUE.CGColor;
    icon.layer.shadowOpacity = 0.55;
    icon.layer.shadowRadius = 18;
    icon.layer.shadowOffset = CGSizeZero;
    [self.view addSubview:icon];
    UILabel *ic = [[UILabel alloc] initWithFrame:icon.bounds];
    ic.text = @"T";
    ic.textColor = UIColor.whiteColor;
    ic.font = [UIFont boldSystemFontOfSize:46];
    ic.textAlignment = NSTextAlignmentCenter;
    [icon addSubview:ic];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(0, icon.frame.origin.y + 98, w, 42)];
    title.text = @"Today内部版";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont boldSystemFontOfSize:32];
    title.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:title];

    CGFloat cw = w - 56, ch = 208, cy = h * 0.455;
    UIView *card = [[UIView alloc] initWithFrame:CGRectMake(28, cy, cw, ch)];
    card.backgroundColor = LC_CARD;
    card.layer.cornerRadius = 16;
    card.layer.borderWidth = 1;
    card.layer.borderColor = LC_BORD.CGColor;
    [self.view addSubview:card];

    UILabel *lab = [[UILabel alloc] initWithFrame:CGRectMake(18, 16, cw - 36, 18)];
    lab.text = @"卡密激活";
    lab.textColor = LC_BLUE;
    lab.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    [card addSubview:lab];

    _field = [[UITextField alloc] initWithFrame:CGRectMake(10, 40, cw - 20, 54)];
    _field.backgroundColor = LC_FIELD;
    _field.layer.cornerRadius = 10;
    _field.layer.borderWidth = 1;
    _field.layer.borderColor = LC_BORD.CGColor;
    _field.textColor = UIColor.whiteColor;
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
    [_field addTarget:self action:@selector(onEdit) forControlEvents:UIControlEventEditingChanged];
    [card addSubview:_field];

    NSString *typed = [[NSUserDefaults standardUserDefaults] objectForKey:kTypedKey];
    NSString *saved = savedCode();
    if ([typed isKindOfClass:[NSString class]] && typed.length) _field.text = typed;
    else if (saved.length) _field.text = saved;

    _btn = [UIButton buttonWithType:UIButtonTypeSystem];
    _btn.frame = CGRectMake(10, 108, cw - 20, 54);
    _btn.backgroundColor = LC_BLUE;
    _btn.layer.cornerRadius = 12;
    [_btn setTitle:@"验 证 激 活" forState:UIControlStateNormal];
    [_btn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    _btn.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    [_btn addTarget:self action:@selector(doVerify) forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:_btn];

    _status = [[UILabel alloc] initWithFrame:CGRectMake(16, 172, cw - 32, 22)];
    _status.textColor = [UIColor colorWithWhite:0.55 alpha:1];
    _status.font = [UIFont systemFontOfSize:12];
    _status.textAlignment = NSTextAlignmentCenter;
    _status.text = saved.length ? @"已加载卡密，请点击验证" : @"";
    [card addSubview:_status];

    UIButton *unbind = [UIButton buttonWithType:UIButtonTypeSystem];
    unbind.frame = CGRectMake(18, h - 118, 120, 34);
    [unbind setTitle:@"解 绑 设 备" forState:UIControlStateNormal];
    [unbind setTitleColor:[UIColor colorWithRed:0.95 green:0.62 blue:0.24 alpha:1]
                 forState:UIControlStateNormal];
    unbind.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    unbind.layer.borderWidth = 1;
    unbind.layer.borderColor = [UIColor colorWithRed:0.42 green:0.28 blue:0.10 alpha:1].CGColor;
    unbind.layer.cornerRadius = 17;
    [unbind addTarget:self action:@selector(doUnbind) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:unbind];

    UIButton *clr = [UIButton buttonWithType:UIButtonTypeSystem];
    clr.frame = CGRectMake(0, h - 92, w, 40);
    [clr setTitle:@"清除已保存的卡密" forState:UIControlStateNormal];
    [clr setTitleColor:[UIColor colorWithWhite:0.40 alpha:1] forState:UIControlStateNormal];
    clr.titleLabel.font = [UIFont systemFontOfSize:12];
    [clr addTarget:self action:@selector(doClear) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:clr];
}

- (void)onEdit {
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    [u setObject:(self.field.text ?: @"") forKey:kTypedKey];
    [u synchronize];
}

- (void)doClear {
    clearLicense();
    _field.text = @"";
    _status.textColor = [UIColor colorWithWhite:0.55 alpha:1];
    _status.text = @"已清除本地卡密";
}

- (void)doUnbind {
    NSString *code = [[_field.text stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]] uppercaseString];
    if (code.length < 8) code = savedCode() ?: @"";
    if (!code.length) {
        _status.textColor = [UIColor colorWithRed:0.95 green:0.35 blue:0.35 alpha:1];
        _status.text = @"请先输入卡密再解绑";
        return;
    }
    UIAlertController *ac = [UIAlertController
        alertControllerWithTitle:@"解绑设备"
                          message:@"解绑后本设备将失去授权，且扣除 6 小时时长。确定解绑？"
                   preferredStyle:UIAlertControllerStyleAlert];
    [ac addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [ac addAction:[UIAlertAction actionWithTitle:@"确定解绑" style:UIAlertActionStyleDestructive
                                       handler:^(UIAlertAction *a) {
        self.status.textColor = [UIColor colorWithWhite:0.55 alpha:1];
        self.status.text = @"正在解绑…";
        [LCNet request:@"unbind" code:code done:^(BOOL reachable, BOOL ok, double exp, NSString *msg) {
            if (!reachable) {
                self.status.textColor = [UIColor colorWithRed:0.95 green:0.35 blue:0.35 alpha:1];
                self.status.text = @"网络不可用，解绑失败";
                return;
            }
            if (ok) {
                BOOL nothing = [msg rangeOfString:@"无需解绑"].location != NSNotFound;
                if (!nothing) { clearLicense(); self.field.text = @""; }
                self.status.textColor = [UIColor colorWithRed:0.95 green:0.72 blue:0.24 alpha:1];
                self.status.text = msg.length ? msg : @"已解绑，请重新激活";
            } else {
                self.status.textColor = [UIColor colorWithRed:0.95 green:0.35 blue:0.35 alpha:1];
                self.status.text = msg.length ? msg : @"解绑失败";
            }
        }];
    }]];
    [self presentViewController:ac animated:YES completion:nil];
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
            stampOnline(code);
            [[NSUserDefaults standardUserDefaults] removeObjectForKey:kTypedKey];
            self->_status.textColor = [UIColor colorWithRed:0.24 green:0.78 blue:0.42 alpha:1];
            self->_status.text = [NSString stringWithFormat:@"验证通过 · 有效期至 %@", fmtTime(exp)];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ LCUnlock(); });
            return;
        }
        if (reachable && !ok) {
            self->_status.textColor = [UIColor colorWithRed:0.95 green:0.35 blue:0.35 alpha:1];
            self->_status.text = msg.length ? msg : @"验证失败";
            return;
        }
        if (!offlineAllowed(code)) {
            self->_status.textColor = [UIColor colorWithRed:0.95 green:0.35 blue:0.35 alpha:1];
            self->_status.text = @"无法连接服务器。设备锁需要联网校验，请检查网络后重试";
            return;
        }
        NSInteger days = verifyDays(code);
        if (days > 0) {
            double act = [[NSDate date] timeIntervalSince1970];
            NSDictionary *old = [[NSUserDefaults standardUserDefaults] objectForKey:kStoreKey];
            if ([old isKindOfClass:[NSDictionary class]] &&
                [old[@"c"] isEqualToString:code] && [old[@"o"] doubleValue] > 0)
                act = [old[@"o"] doubleValue];
            double e2 = act + days * 86400.0;
            saveLicense(code, e2);
            self->_status.textColor = [UIColor colorWithRed:0.95 green:0.72 blue:0.24 alpha:1];
            self->_status.text = [NSString stringWithFormat:@"离线验证通过 · 有效期至 %@", fmtTime(e2)];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ LCUnlock(); });
        } else {
            self->_status.textColor = [UIColor colorWithRed:0.95 green:0.35 blue:0.35 alpha:1];
            self->_status.text = @"卡密格式无效";
        }
    }];
}

@end

#pragma mark - 窗口可见性硬锁

static void (*orig_setHidden)(id, SEL, BOOL) = NULL;

// 允许显示的窗口：我们的锁窗口 / 键盘 / 状态栏
static BOOL LCWindowAllowed(id win) {
    if (win == gLockWin) return YES;
    NSString *n = NSStringFromClass([win class]);
    if ([n containsString:@"Keyboard"]) return YES;
    if ([n containsString:@"TextEffects"]) return YES;
    if ([n containsString:@"StatusBar"]) return YES;
    if ([n containsString:@"Alert"]) return YES;
    return NO;
}

static void my_setHidden(id self, SEL _cmd, BOOL h) {
    if (!gUnlocked && h == NO && !LCWindowAllowed(self)) {
        if (orig_setHidden) orig_setHidden(self, _cmd, YES);
        return;
    }
    if (orig_setHidden) orig_setHidden(self, _cmd, h);
}

#pragma mark - 锁控制

static void LCStartGuard(void);

static void LCHideAppWindows(BOOL hide) {
    for (UIWindow *w in [[UIApplication sharedApplication] windows]) {
        if (w == gLockWin) continue;
        w.hidden = hide;
    }
}

static UIWindowScene *LCScene(void) {
    if (@available(iOS 13.0, *)) {
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            if ([sc isKindOfClass:[UIWindowScene class]] &&
                sc.activationState != UISceneActivationStateUnattached)
                return (UIWindowScene *)sc;
        }
    }
    return nil;
}

static void LCUnlock(void) {
    if (gUnlocked) return;
    gUnlocked = YES;
    if (gGuard) { [gGuard invalidate]; gGuard = nil; }
    if (gLockWin) {
        gLockWin.hidden = YES;
        gLockWin.rootViewController = nil;
        gLockWin = nil;
    }
    LCHideAppWindows(NO);
    if (gAppWin) [gAppWin makeKeyAndVisible];
    if (gBeat) [gBeat invalidate];
    gBeat = [NSTimer scheduledTimerWithTimeInterval:1800 repeats:YES block:^(NSTimer *t) {
        NSString *c = savedCode();
        if (!c.length) return;
        [LCNet request:@"heartbeat" code:c done:^(BOOL reachable, BOOL ok, double exp, NSString *msg) {
            if (!reachable) return;
            if (ok && exp > 0) { saveLicense(c, exp); stampOnline(c); return; }
            clearLicense();
            gUnlocked = NO;
            LCInstallLock();
        }];
    }];
    NSLog(@"[TodayHook] 已解锁");
}

static void LCInstallLock(void) {
    if (gUnlocked) return;
    if (gLockWin && gLockWin.rootViewController) {
        gLockWin.hidden = NO;
        if (![gLockWin isKeyWindow]) [gLockWin makeKeyAndVisible];
        LCHideAppWindows(YES);
        return;
    }
    UIWindowScene *sc = LCScene();
    UIWindow *w = nil;
    if (sc) {
        w = [[UIWindow alloc] initWithWindowScene:sc];
        w.frame = sc.coordinateSpace.bounds;
    } else {
        w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    }
    w.windowLevel = UIWindowLevelAlert + 10000;
    w.backgroundColor = LC_BG;
    w.rootViewController = [[LCLockVC alloc] init];
    w.hidden = NO;
    gLockWin = w;
    [w makeKeyAndVisible];
    LCHideAppWindows(YES);
    LCStartGuard();
    NSLog(@"[TodayHook] 锁窗口已安装 scene=%@", sc ? @"YES" : @"NO");
}

static void LCGuardTick(void) {
    if (gUnlocked) {
        if (gGuard) { [gGuard invalidate]; gGuard = nil; }
        return;
    }
    if (!gLockWin || !gLockWin.rootViewController) { LCInstallLock(); return; }
    if (@available(iOS 13.0, *)) {
        if (!gLockWin.windowScene) {
            gLockWin.hidden = YES;
            gLockWin.rootViewController = nil;
            gLockWin = nil;
            LCInstallLock();
            return;
        }
    }
    if (gLockWin.hidden) gLockWin.hidden = NO;
    if (gLockWin.windowLevel < UIWindowLevelAlert + 10000)
        gLockWin.windowLevel = UIWindowLevelAlert + 10000;
    if (![gLockWin isKeyWindow]) [gLockWin makeKeyAndVisible];
    // 其它窗口一律压回隐藏（走原始实现，避免被自己的钩子吞掉）
    for (UIWindow *w in [[UIApplication sharedApplication] windows]) {
        if (w == gLockWin) continue;
        if (orig_setHidden) orig_setHidden(w, @selector(setHidden:), YES);
    }
}

static void LCStartGuard(void) {
    if (gGuard) return;
    gGuard = [NSTimer scheduledTimerWithTimeInterval:0.25 repeats:YES block:^(NSTimer *t) {
        LCGuardTick();
    }];
}

#pragma mark - Hook

static void (*orig_makeKeyAndVisible)(id, SEL) = NULL;

static void my_makeKeyAndVisible(id self, SEL _cmd) {
    if (orig_makeKeyAndVisible) orig_makeKeyAndVisible(self, _cmd);
    if (gUnlocked) return;
    if (self != gLockWin) gAppWin = (UIWindow *)self;
    if (!gLockWin) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.05 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (!gUnlocked) LCInstallLock();
        });
    }
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
    Method hm = wc ? class_getInstanceMethod(wc, @selector(setHidden:)) : NULL;
    if (hm) {
        orig_setHidden = (void (*)(id, SEL, BOOL))method_getImplementation(hm);
        method_setImplementation(hm, (IMP)my_setHidden);
        NSLog(@"[TodayHook] setHidden 硬锁已挂载");
    }
    hookIfExists("XQGate", @selector(showGate:), (IMP)gate_showGate);
    hookIfExists("XQGate", @selector(startHeartbeat), (IMP)gate_noop);
    hookIfExists("XQGate", @selector(doBeat), (IMP)gate_noop);

    if (@available(iOS 13.0, *)) {
        [[NSNotificationCenter defaultCenter]
            addObserverForName:UISceneDidActivateNotification object:nil
                          queue:[NSOperationQueue mainQueue]
                     usingBlock:^(NSNotification *n) {
            if (!gUnlocked) LCInstallLock();
        }];
    }
    NSLog(@"[TodayHook] v9 loaded");
}
