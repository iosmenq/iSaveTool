/*
***********************************
* iSaveTool.m
* Coded By iosmen (C) 2025
* APOLLO SAVE TOOL FOR IOS LOL :)
* APOLLO GITHUB: https://github.com/bucanero/apollo-ps4
* MY GITHUB: https://github.com/iosmenq
* VERSION 1.118
* SORRY FOR BETA HAVE BUGS ;(
* MAKE NEED CLANG AND iPHONEOS SDK 13.0=> THEN RUN "script.sh"
* YOU HAVE A ROOT CREATE THIS FOLDER "/mnt/data/save"
***********************************
*/

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import "ISMainViewController.h"
#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <MobileCoreServices/MobileCoreServices.h>
#import <sqlite3.h>
#import <CommonCrypto/CommonCrypto.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <dirent.h>
#import <errno.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <ifaddrs.h>

// MARK: - Constants
#define kDefaultSavePath @"/mnt/data/save"
#define kAppDataPath @"/private/var/mobile/Containers/Data/Application"
#define kBackupPath @"/var/mobile/Library/iSaveTool/backups"
#define kLogPath @"/var/mobile/Library/iSaveTool/logs"
#define kWebDAVPath @"/var/mobile/Library/iSaveTool/webdav"
#define kEncryptedPath @"/var/mobile/Library/iSaveTool/encrypted"
#define kTemplatesPath @"/var/mobile/Library/iSaveTool/templates"
#define kFavoritesPath @"/var/mobile/Library/iSaveTool/favorites.plist"
#define IS_COLOR(r,g,b,a) [UIColor colorWithRed:(r)/255.0 green:(g)/255.0 blue:(b)/255.0 alpha:(a)]
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)

// MARK: - Theme Manager
static BOOL _isDarkTheme = YES;
static NSString *_customThemeColor = nil;

@interface ISTheme : NSObject
+ (BOOL)isDarkTheme;
+ (void)setDarkTheme:(BOOL)dark;
+ (void)setCustomAccentColor:(NSString *)hexColor;
+ (UIColor *)primaryBackground;
+ (UIColor *)secondaryBackground;
+ (UIColor *)accentColor;
+ (UIColor *)highlightColor;
+ (UIColor *)textPrimary;
+ (UIColor *)textSecondary;
+ (UIColor *)tableViewCellBackground;
+ (UIColor *)hexViewBackground;
+ (UIColor *)hexTextColor;
+ (UIColor *)hexOffsetColor;
+ (UIColor *)hexAsciiColor;
+ (UIColor *)successColor;
+ (UIColor *)errorColor;
+ (UIColor *)warningColor;
+ (UIColor *)infoColor;
+ (UIColor *)colorFromHex:(NSString *)hex;
@end

@implementation ISTheme
+ (BOOL)isDarkTheme { return _isDarkTheme; }
+ (void)setDarkTheme:(BOOL)dark { _isDarkTheme = dark; }
+ (void)setCustomAccentColor:(NSString *)hexColor { _customThemeColor = hexColor; }

+ (UIColor *)primaryBackground {
    return _isDarkTheme ? IS_COLOR(14, 23, 38, 1.0) : [UIColor whiteColor];
}

+ (UIColor *)secondaryBackground {
    return _isDarkTheme ? IS_COLOR(17, 24, 39, 1.0) : IS_COLOR(242, 242, 247, 1.0);
}

+ (UIColor *)accentColor {
    if (_customThemeColor) {
        return [self colorFromHex:_customThemeColor];
    }
    return _isDarkTheme ? IS_COLOR(0, 191, 165, 1.0) : IS_COLOR(0, 122, 255, 1.0);
}

+ (UIColor *)highlightColor {
    return _isDarkTheme ? IS_COLOR(255, 209, 102, 1.0) : IS_COLOR(255, 149, 0, 1.0);
}

+ (UIColor *)textPrimary {
    return _isDarkTheme ? [UIColor whiteColor] : [UIColor blackColor];
}

+ (UIColor *)textSecondary {
    return _isDarkTheme ? IS_COLOR(200, 200, 200, 1.0) : IS_COLOR(60, 60, 67, 0.6);
}

+ (UIColor *)tableViewCellBackground {
    return _isDarkTheme ? IS_COLOR(25, 32, 47, 1.0) : [UIColor whiteColor];
}

+ (UIColor *)hexViewBackground {
    return _isDarkTheme ? IS_COLOR(10, 15, 25, 1.0) : IS_COLOR(248, 248, 248, 1.0);
}

+ (UIColor *)hexTextColor {
    return _isDarkTheme ? [UIColor whiteColor] : [UIColor blackColor];
}

+ (UIColor *)hexOffsetColor {
    return _isDarkTheme ? IS_COLOR(100, 200, 255, 1.0) : IS_COLOR(0, 100, 200, 1.0);
}

+ (UIColor *)hexAsciiColor {
    return _isDarkTheme ? IS_COLOR(255, 209, 102, 1.0) : IS_COLOR(255, 149, 0, 1.0);
}

+ (UIColor *)successColor {
    return IS_COLOR(52, 199, 89, 1.0);
}

+ (UIColor *)errorColor {
    return IS_COLOR(255, 59, 48, 1.0);
}

+ (UIColor *)warningColor {
    return IS_COLOR(255, 204, 0, 1.0);
}

+ (UIColor *)infoColor {
    return IS_COLOR(0, 122, 255, 1.0);
}

+ (UIColor *)colorFromHex:(NSString *)hex {
    NSString *cleanHex = [hex stringByReplacingOccurrencesOfString:@"#" withString:@""];
    cleanHex = [cleanHex stringByReplacingOccurrencesOfString:@"0x" withString:@""];
    
    unsigned rgbValue = 0;
    NSScanner *scanner = [NSScanner scannerWithString:cleanHex];
    [scanner scanHexInt:&rgbValue];
    
    return [UIColor colorWithRed:((rgbValue & 0xFF0000) >> 16)/255.0
                           green:((rgbValue & 0xFF00) >> 8)/255.0
                            blue:(rgbValue & 0xFF)/255.0
                           alpha:1.0];
}
@end

// MARK: - Encryption Manager
@interface ISEncryptionManager : NSObject
+ (instancetype)shared;
+ (NSData *)encryptData:(NSData *)data password:(NSString *)password;
+ (NSData *)decryptData:(NSData *)encryptedData password:(NSString *)password;
+ (NSString *)hashString:(NSString *)string algorithm:(NSString *)algorithm;
+ (NSString *)generateRandomKey;
+ (BOOL)validatePassword:(NSString *)password;
@end

@implementation ISEncryptionManager {
    NSData *_masterKey;
}

+ (instancetype)shared {
    static ISEncryptionManager *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[ISEncryptionManager alloc] init];
    });
    return shared;
}

+ (NSData *)encryptData:(NSData *)data password:(NSString *)password {
    if (!data || !password) return nil;
    
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *salt = [NSMutableData dataWithLength:8];
    SecRandomCopyBytes(kSecRandomDefault, 8, salt.mutableBytes);
    
    // Derive key
    NSMutableData *key = [NSMutableData dataWithLength:kCCKeySizeAES256];
    NSMutableData *iv = [NSMutableData dataWithLength:kCCBlockSizeAES128];
    
    CCKeyDerivationPBKDF(kCCPBKDF2,
                        passwordData.bytes, passwordData.length,
                        salt.bytes, salt.length,
                        kCCPRFHmacAlgSHA256,
                        10000,
                        key.mutableBytes, key.length);
    
    SecRandomCopyBytes(kSecRandomDefault, iv.length, iv.mutableBytes);
    
    // Encrypt
    size_t bufferSize = data.length + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t encryptedSize = 0;
    CCCryptorStatus status = CCCrypt(kCCEncrypt,
                                    kCCAlgorithmAES,
                                    kCCOptionPKCS7Padding,
                                    key.bytes, key.length,
                                    iv.bytes,
                                    data.bytes, data.length,
                                    buffer, bufferSize,
                                    &encryptedSize);
    
    if (status != kCCSuccess) {
        free(buffer);
        return nil;
    }
    
    // Combine salt + iv + encrypted data
    NSMutableData *result = [NSMutableData data];
    [result appendData:salt];
    [result appendData:iv];
    [result appendBytes:buffer length:encryptedSize];
    
    free(buffer);
    return [result copy];
}

+ (NSData *)decryptData:(NSData *)encryptedData password:(NSString *)password {
    if (encryptedData.length < 8 + kCCBlockSizeAES128) return nil;
    
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    
    // Extract salt and iv
    NSData *salt = [encryptedData subdataWithRange:NSMakeRange(0, 8)];
    NSData *iv = [encryptedData subdataWithRange:NSMakeRange(8, kCCBlockSizeAES128)];
    NSData *cipherText = [encryptedData subdataWithRange:NSMakeRange(8 + kCCBlockSizeAES128,
                                                                     encryptedData.length - (8 + kCCBlockSizeAES128))];
    
    // Derive key
    NSMutableData *key = [NSMutableData dataWithLength:kCCKeySizeAES256];
    
    CCKeyDerivationPBKDF(kCCPBKDF2,
                        passwordData.bytes, passwordData.length,
                        salt.bytes, salt.length,
                        kCCPRFHmacAlgSHA256,
                        10000,
                        key.mutableBytes, key.length);
    
    // Decrypt
    size_t bufferSize = cipherText.length + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t decryptedSize = 0;
    CCCryptorStatus status = CCCrypt(kCCDecrypt,
                                    kCCAlgorithmAES,
                                    kCCOptionPKCS7Padding,
                                    key.bytes, key.length,
                                    iv.bytes,
                                    cipherText.bytes, cipherText.length,
                                    buffer, bufferSize,
                                    &decryptedSize);
    
    if (status != kCCSuccess) {
        free(buffer);
        return nil;
    }
    
    NSData *result = [NSData dataWithBytes:buffer length:decryptedSize];
    free(buffer);
    return result;
}

+ (NSString *)hashString:(NSString *)string algorithm:(NSString *)algorithm {
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    
    if ([algorithm isEqualToString:@"MD5"]) {
        unsigned char digest[CC_MD5_DIGEST_LENGTH];
        CC_MD5(data.bytes, (CC_LONG)data.length, digest);
        return [self hexStringFromBytes:digest length:CC_MD5_DIGEST_LENGTH];
    }
    else if ([algorithm isEqualToString:@"SHA1"]) {
        unsigned char digest[CC_SHA1_DIGEST_LENGTH];
        CC_SHA1(data.bytes, (CC_LONG)data.length, digest);
        return [self hexStringFromBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    }
    else if ([algorithm isEqualToString:@"SHA256"]) {
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
        return [self hexStringFromBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    }
    
    return nil;
}

+ (NSString *)hexStringFromBytes:(unsigned char *)bytes length:(int)length {
    NSMutableString *hexString = [NSMutableString string];
    for (int i = 0; i < length; i++) {
        [hexString appendFormat:@"%02x", bytes[i]];
    }
    return [hexString copy];
}

+ (NSString *)generateRandomKey {
    NSMutableData *data = [NSMutableData dataWithLength:32];
    SecRandomCopyBytes(kSecRandomDefault, 32, data.mutableBytes);
    return [self hexStringFromBytes:data.bytes length:32];
}

+ (BOOL)validatePassword:(NSString *)password {
    if (password.length < 6) return NO;
    if (password.length > 128) return NO;
    
    // Check for at least one number and one letter
    NSCharacterSet *letters = [NSCharacterSet letterCharacterSet];
    NSCharacterSet *digits = [NSCharacterSet decimalDigitCharacterSet];
    
    BOOL hasLetter = [password rangeOfCharacterFromSet:letters].location != NSNotFound;
    BOOL hasDigit = [password rangeOfCharacterFromSet:digits].location != NSNotFound;
    
    return hasLetter && hasDigit;
}
@end

// MARK: - Logger
@interface ISLogger : NSObject
+ (void)setup;
+ (void)log:(NSString *)format, ...;
+ (void)logError:(NSString *)format, ...;
+ (void)logWarning:(NSString *)format, ...;
+ (void)logInfo:(NSString *)format, ...;
+ (void)logFileOperation:(NSString *)operation path:(NSString *)path;
+ (NSArray *)getLogEntries;
+ (void)clearLogs;
@end

@implementation ISLogger

+ (void)setup {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:kLogPath]) {
        [fm createDirectoryAtPath:kLogPath withIntermediateDirectories:YES attributes:nil error:nil];
    }
}

+ (void)writeLog:(NSString *)message level:(NSString *)level {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        [formatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
        NSString *timestamp = [formatter stringFromDate:[NSDate date]];
        NSString *logLine = [NSString stringWithFormat:@"[%@] [%@] %@\n", timestamp, level, message];
        
        NSString *logFile = [NSString stringWithFormat:@"%@/isavetool.log", kLogPath];
        NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:logFile];
        if (handle) {
            [handle seekToEndOfFile];
            [handle writeData:[logLine dataUsingEncoding:NSUTF8StringEncoding]];
            [handle closeFile];
        } else {
            [logLine writeToFile:logFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        
        NSLog(@"%@", logLine);
    });
}

+ (void)log:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    [self writeLog:message level:@"INFO"];
}

+ (void)logError:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    [self writeLog:message level:@"ERROR"];
}

+ (void)logWarning:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    [self writeLog:message level:@"WARN"];
}

+ (void)logInfo:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    [self writeLog:message level:@"INFO"];
}

+ (void)logFileOperation:(NSString *)operation path:(NSString *)path {
    [self log:@"%@: %@", operation, path];
}

+ (NSArray *)getLogEntries {
    NSString *logFile = [NSString stringWithFormat:@"%@/isavetool.log", kLogPath];
    NSString *content = [NSString stringWithContentsOfFile:logFile encoding:NSUTF8StringEncoding error:nil];
    
    if (!content) return @[];
    
    NSArray *lines = [content componentsSeparatedByString:@"\n"];
    NSMutableArray *entries = [NSMutableArray array];
    
    for (NSString *line in lines) {
        if (line.length > 0) {
            [entries addObject:line];
        }
    }
    
    return [[entries reverseObjectEnumerator] allObjects];
}

+ (void)clearLogs {
    NSString *logFile = [NSString stringWithFormat:@"%@/isavetool.log", kLogPath];
    [[NSFileManager defaultManager] removeItemAtPath:logFile error:nil];
    [self setup];
}
@end

// MARK: - Audio Manager
@interface ISAudioManager : NSObject
+ (instancetype)shared;
- (void)playBackgroundMusic;
- (void)pauseBackgroundMusic;
- (void)stopBackgroundMusic;
- (BOOL)isMusicPlaying;
- (void)toggleMusic;
- (void)playSoundEffect:(NSString *)effect;
@property (nonatomic, assign) BOOL musicEnabled;
@property (nonatomic, assign) BOOL soundEffectsEnabled;
@end

@implementation ISAudioManager {
    AVAudioPlayer *_audioPlayer;
    BOOL _shouldPlayMusic;
    SystemSoundID _clickSound;
    SystemSoundID _successSound;
    SystemSoundID _errorSound;
}

+ (instancetype)shared {
    static ISAudioManager *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[ISAudioManager alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _musicEnabled = YES;
        _soundEffectsEnabled = YES;
        _shouldPlayMusic = YES;
        
        [self setupAudioSession];
        [self setupAudioPlayer];
        [self setupSoundEffects];
    }
    return self;
}

- (void)setupAudioSession {
    @try {
        AVAudioSession *session = [AVAudioSession sharedInstance];
        [session setCategory:AVAudioSessionCategoryPlayback 
                       mode:AVAudioSessionModeDefault 
                    options:AVAudioSessionCategoryOptionMixWithOthers error:nil];
        [session setActive:YES error:nil];
    } @catch (NSException *exception) {
        [ISLogger logError:@"Audio session setup failed: %@", exception.reason];
    }
}

- (void)setupAudioPlayer {
    NSString *musicPath = @"/Applications/iSaveTool.app/bg.mp3";
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:musicPath]) {
        musicPath = [[NSBundle mainBundle] pathForResource:@"bg" ofType:@"mp3"];
    }
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:musicPath]) {
        [ISLogger log:@"Background music file not found"];
        return;
    }
    
    NSURL *musicURL = [NSURL fileURLWithPath:musicPath];
    
    NSError *error = nil;
    _audioPlayer = [[AVAudioPlayer alloc] initWithContentsOfURL:musicURL error:&error];
    
    if (error) {
        [ISLogger logError:@"Failed to create audio player: %@", error.localizedDescription];
        return;
    }
    
    _audioPlayer.numberOfLoops = -1;
    _audioPlayer.volume = 0.3;
    [_audioPlayer prepareToPlay];
    
    [ISLogger log:@"Audio player initialized"];
}

- (void)setupSoundEffects {
    // Create click sound
    NSURL *clickURL = [[NSBundle mainBundle] URLForResource:@"click" withExtension:@"caf"];
    if (!clickURL) {
        // Create synthetic click sound
        AudioServicesCreateSystemSoundID((__bridge CFURLRef)[NSURL fileURLWithPath:@"/System/Library/Audio/UISounds/Tock.caf"], &_clickSound);
    } else {
        AudioServicesCreateSystemSoundID((__bridge CFURLRef)clickURL, &_clickSound);
    }
    
    // Success sound
    AudioServicesCreateSystemSoundID((__bridge CFURLRef)[NSURL fileURLWithPath:@"/System/Library/Audio/UISounds/nano/3rdParty_Success_Haptic.caf"], &_successSound);
    
    // Error sound
    AudioServicesCreateSystemSoundID((__bridge CFURLRef)[NSURL fileURLWithPath:@"/System/Library/Audio/UISounds/nano/3rdParty_Failure_Haptic.caf"], &_errorSound);
}

- (void)playBackgroundMusic {
    if (!_musicEnabled) return;
    
    if (_audioPlayer && ![_audioPlayer isPlaying]) {
        [_audioPlayer play];
        _shouldPlayMusic = YES;
        [ISLogger log:@"Background music started"];
    }
}

- (void)pauseBackgroundMusic {
    if (_audioPlayer && [_audioPlayer isPlaying]) {
        [_audioPlayer pause];
        _shouldPlayMusic = NO;
        [ISLogger log:@"Background music paused"];
    }
}

- (void)stopBackgroundMusic {
    if (_audioPlayer) {
        [_audioPlayer stop];
        _audioPlayer.currentTime = 0;
        _shouldPlayMusic = NO;
        [ISLogger log:@"Background music stopped"];
    }
}

- (BOOL)isMusicPlaying {
    return _audioPlayer ? [_audioPlayer isPlaying] : NO;
}

- (void)toggleMusic {
    _musicEnabled = !_musicEnabled;
    
    if (_musicEnabled) {
        [self playBackgroundMusic];
    } else {
        [self pauseBackgroundMusic];
    }
    
    [ISLogger log:@"Music toggled: %@", _musicEnabled ? @"ON" : @"OFF"];
}

- (void)playSoundEffect:(NSString *)effect {
    if (!_soundEffectsEnabled) return;
    
    if ([effect isEqualToString:@"click"]) {
        AudioServicesPlaySystemSound(_clickSound);
    } else if ([effect isEqualToString:@"success"]) {
        AudioServicesPlaySystemSound(_successSound);
    } else if ([effect isEqualToString:@"error"]) {
        AudioServicesPlaySystemSound(_errorSound);
    }
}

- (void)applicationDidBecomeActive {
    if (_musicEnabled && _shouldPlayMusic) {
        [self playBackgroundMusic];
    }
}

- (void)applicationWillResignActive {
    [self pauseBackgroundMusic];
}

@end

// MARK: - App Info Model
@interface ISAppInfo : NSObject
@property (nonatomic, strong) NSString *appName;
@property (nonatomic, strong) NSString *bundleId;
@property (nonatomic, strong) NSString *appId;
@property (nonatomic, strong) NSString *dataPath;
@property (nonatomic, strong) NSArray *plistFiles;
@property (nonatomic, strong) NSArray *saveFiles;
@property (nonatomic, assign) long long totalSize;
@property (nonatomic, strong) NSDate *lastModified;
@end

@implementation ISAppInfo
@end

// MARK: - File Manager
@interface ISFileManager : NSObject
+ (instancetype)shared;
- (NSArray *)getSaveFilesAtPath:(NSString *)path;
- (NSArray *)getInstalledApps;
- (NSArray *)getAppPlistFiles:(NSString *)appDataPath;
- (NSArray *)findSaveFilesInPath:(NSString *)path;
- (NSString *)getAppNameFromBundleId:(NSString *)bundleId;
- (BOOL)backupFile:(NSString *)filePath error:(NSError **)error;
- (BOOL)restoreBackup:(NSString *)backupPath toPath:(NSString *)destination error:(NSError **)error;
- (NSArray *)getBackupsForFile:(NSString *)filePath;
- (NSData *)readFileAtPath:(NSString *)path error:(NSError **)error;
- (BOOL)writeData:(NSData *)data toPath:(NSString *)path error:(NSError **)error;
- (BOOL)isBinaryPlist:(NSData *)data;
- (id)parsePlistData:(NSData *)data error:(NSError **)error;
- (BOOL)savePlistObject:(id)object toPath:(NSString *)path binary:(BOOL)binary error:(NSError **)error;
- (BOOL)exportToHDD:(NSData *)data fileName:(NSString *)fileName error:(NSError **)error;
- (NSDictionary *)getFileInfo:(NSString *)path;
- (long long)calculateFolderSize:(NSString *)path;
- (NSArray *)searchFiles:(NSString *)searchText inPath:(NSString *)path;
- (NSArray *)getDuplicateFilesInPath:(NSString *)path;
- (BOOL)compressFile:(NSString *)sourcePath toPath:(NSString *)destPath error:(NSError **)error;
- (BOOL)decompressFile:(NSString *)sourcePath toPath:(NSString *)destPath error:(NSError **)error;
- (NSString *)getFileChecksum:(NSString *)path algorithm:(NSString *)algorithm;
- (BOOL)encryptFile:(NSString *)sourcePath toPath:(NSString *)destPath password:(NSString *)password error:(NSError **)error;
- (BOOL)decryptFile:(NSString *)sourcePath toPath:(NSString *)destPath password:(NSString *)password error:(NSError **)error;
- (NSArray *)batchOperation:(NSArray *)files operation:(NSString *)operation error:(NSError **)error;
@end

@implementation ISFileManager {
    NSFileManager *_fm;
}

+ (instancetype)shared {
    static ISFileManager *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[ISFileManager alloc] init];
    });
    return shared;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _fm = [NSFileManager defaultManager];
        [self createDirectoriesIfNeeded];
    }
    return self;
}

- (void)createDirectoriesIfNeeded {
    NSArray *paths = @[kBackupPath, kLogPath, kWebDAVPath, kEncryptedPath, kTemplatesPath];
    for (NSString *path in paths) {
        if (![_fm fileExistsAtPath:path]) {
            [_fm createDirectoryAtPath:path withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @0755} error:nil];
        }
    }
}

- (NSArray *)getInstalledApps {
    NSMutableArray *apps = [NSMutableArray array];
    
    NSError *error = nil;
    NSArray *appDirs = [_fm contentsOfDirectoryAtPath:kAppDataPath error:&error];
    
    if (error) {
        [ISLogger logError:@"Failed to read app data directory: %@", error.localizedDescription];
        return @[];
    }
    
    for (NSString *appId in appDirs) {
        NSString *appDataPath = [kAppDataPath stringByAppendingPathComponent:appId];
        NSDictionary *attrs = [_fm attributesOfItemAtPath:appDataPath error:nil];
        
        if (attrs[NSFileType] != NSFileTypeDirectory) {
            continue;
        }
        
        NSString *metadataPath = [appDataPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
        
        if (![_fm fileExistsAtPath:metadataPath]) {
            continue;
        }
        
        NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
        if (!metadata) {
            continue;
        }
        
        NSString *bundleId = metadata[@"MCMMetadataIdentifier"];
        if (!bundleId) {
            continue;
        }
        
        ISAppInfo *appInfo = [[ISAppInfo alloc] init];
        appInfo.appId = appId;
        appInfo.bundleId = bundleId;
        appInfo.dataPath = appDataPath;
        appInfo.appName = [self getAppNameFromBundleId:bundleId];
        
        appInfo.plistFiles = [self getAppPlistFiles:appDataPath];
        appInfo.saveFiles = [self findSaveFilesInPath:appDataPath];
        appInfo.totalSize = [self calculateFolderSize:appDataPath];
        appInfo.lastModified = attrs[NSFileModificationDate];
        
        if (appInfo.plistFiles.count > 0 || appInfo.saveFiles.count > 0) {
            [apps addObject:appInfo];
        }
    }
    
    [apps sortUsingComparator:^NSComparisonResult(ISAppInfo *obj1, ISAppInfo *obj2) {
        return [obj1.appName compare:obj2.appName];
    }];
    
    return [apps copy];
}

- (NSString *)getAppNameFromBundleId:(NSString *)bundleId {
    // Predefined mappings
    NSDictionary *appNames = @{
        @"com.facebook": @"Facebook",
        @"com.atebits": @"Twitter",
        @"com.burbn.instagram": @"Instagram",
        @"com.google.ios.youtube": @"YouTube",
        @"com.google.ios.chrome": @"Chrome",
        @"com.apple.mobilesafari": @"Safari",
        @"com.apple.mobilemail": @"Mail",
        @"com.apple.MobileSMS": @"Messages",
        @"com.apple.mobileslideshow": @"Photos",
        @"com.apple.camera": @"Camera",
        @"com.apple.mobilecal": @"Calendar",
        @"com.apple.mobilenotes": @"Notes",
        @"com.apple.compass": @"Compass",
        @"com.apple.mobiletimer": @"Clock",
        @"com.apple.weather": @"Weather",
        @"com.apple.calculator": @"Calculator",
        @"com.apple.AppStore": @"App Store",
        @"com.apple.Preferences": @"Settings"
    };
    
    for (NSString *prefix in appNames.allKeys) {
        if ([bundleId hasPrefix:prefix]) {
            return appNames[prefix];
        }
    }
    
    NSArray *components = [bundleId componentsSeparatedByString:@"."];
    if (components.count > 0) {
        NSString *lastComponent = components.lastObject;
        if (lastComponent.length > 0) {
            return [[lastComponent substringToIndex:1].uppercaseString stringByAppendingString:[lastComponent substringFromIndex:1]];
        }
    }
    
    return bundleId;
}

- (NSArray *)getAppPlistFiles:(NSString *)appDataPath {
    NSMutableArray *plistFiles = [NSMutableArray array];
    
    @try {
        NSDirectoryEnumerator *enumerator = [_fm enumeratorAtPath:appDataPath];
        NSString *file;
        
        while ((file = [enumerator nextObject])) {
            if ([file.pathExtension.lowercaseString isEqualToString:@"plist"] || [file hasSuffix:@".plist"]) {
                NSString *fullPath = [appDataPath stringByAppendingPathComponent:file];
                NSDictionary *attrs = [_fm attributesOfItemAtPath:fullPath error:nil];
                
                NSMutableDictionary *fileInfo = [NSMutableDictionary dictionary];
                fileInfo[@"name"] = file.lastPathComponent;
                fileInfo[@"path"] = fullPath;
                fileInfo[@"size"] = attrs[NSFileSize] ?: @0;
                fileInfo[@"modified"] = attrs[NSFileModificationDate] ?: [NSDate date];
                fileInfo[@"relativePath"] = file;
                
                [plistFiles addObject:fileInfo];
            }
        }
    } @catch (NSException *exception) {
        [ISLogger logError:@"Error scanning app directory: %@", exception.reason];
    }
    
    return [plistFiles copy];
}

- (NSArray *)findSaveFilesInPath:(NSString *)path {
    NSMutableArray *saveFiles = [NSMutableArray array];
    
    @try {
        NSArray *saveExtensions = @[@"sav", @"save", @"dat", @"data", @"game", @"slot", @"bin", @"json"];
        NSDirectoryEnumerator *enumerator = [_fm enumeratorAtPath:path];
        NSString *file;
        
        while ((file = [enumerator nextObject])) {
            NSString *ext = file.pathExtension.lowercaseString;
            if ([saveExtensions containsObject:ext]) {
                NSString *fullPath = [path stringByAppendingPathComponent:file];
                NSDictionary *attrs = [_fm attributesOfItemAtPath:fullPath error:nil];
                
                NSMutableDictionary *fileInfo = [NSMutableDictionary dictionary];
                fileInfo[@"name"] = file.lastPathComponent;
                fileInfo[@"path"] = fullPath;
                fileInfo[@"size"] = attrs[NSFileSize] ?: @0;
                fileInfo[@"modified"] = attrs[NSFileModificationDate] ?: [NSDate date];
                fileInfo[@"relativePath"] = file;
                
                [saveFiles addObject:fileInfo];
            }
        }
    } @catch (NSException *exception) {
        [ISLogger logError:@"Error scanning for save files: %@", exception.reason];
    }
    
    return [saveFiles copy];
}

- (NSArray *)getSaveFilesAtPath:(NSString *)path {
    NSError *error = nil;
    NSArray *contents = [_fm contentsOfDirectoryAtPath:path error:&error];
    
    if (error) {
        [ISLogger logError:@"Failed to read directory %@: %@", path, error.localizedDescription];
        return @[];
    }
    
    NSMutableArray *files = [NSMutableArray array];
    for (NSString *item in contents) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        NSDictionary *attrs = [_fm attributesOfItemAtPath:fullPath error:nil];
        
        if (attrs[NSFileType] == NSFileTypeDirectory) {
            continue;
        }
        
        if ([item.pathExtension.lowercaseString isEqualToString:@"plist"] || 
            [item.pathExtension.lowercaseString isEqualToString:@"bak"] ||
            [item hasSuffix:@".plist"] ||
            [item.pathExtension.lowercaseString isEqualToString:@"sav"] ||
            [item.pathExtension.lowercaseString isEqualToString:@"save"] ||
            [item.pathExtension.lowercaseString isEqualToString:@"dat"]) {
            
            NSMutableDictionary *fileInfo = [NSMutableDictionary dictionary];
            fileInfo[@"name"] = item;
            fileInfo[@"path"] = fullPath;
            fileInfo[@"size"] = attrs[NSFileSize] ?: @0;
            fileInfo[@"modified"] = attrs[NSFileModificationDate] ?: [NSDate date];
            
            NSData *data = [NSData dataWithContentsOfFile:fullPath options:0 error:nil];
            if (data) {
                fileInfo[@"isBinary"] = @([self isBinaryPlist:data]);
            }
            
            [files addObject:fileInfo];
        }
    }
    
    [files sortUsingComparator:^NSComparisonResult(NSDictionary *obj1, NSDictionary *obj2) {
        NSDate *date1 = obj1[@"modified"];
        NSDate *date2 = obj2[@"modified"];
        return [date2 compare:date1];
    }];
    
    return [files copy];
}

- (BOOL)backupFile:(NSString *)filePath error:(NSError **)error {
    if (![_fm fileExistsAtPath:filePath]) {
        if (error) *error = [NSError errorWithDomain:@"ISFileManager" code:404 
                                             userInfo:@{NSLocalizedDescriptionKey: @"File not found"}];
        return NO;
    }
    
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"yyyyMMdd-HHmmss"];
    NSString *timestamp = [formatter stringFromDate:[NSDate date]];
    NSString *fileName = [filePath.lastPathComponent stringByAppendingFormat:@".%@.bak", timestamp];
    NSString *backupPath = [kBackupPath stringByAppendingPathComponent:fileName];
    
    BOOL success = [_fm copyItemAtPath:filePath toPath:backupPath error:error];
    
    if (success) {
        [ISLogger logFileOperation:@"Backup created" path:backupPath];
        
        if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"10.0")) {
            UIImpactFeedbackGenerator *generator = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
            [generator impactOccurred];
        }
        
        [[ISAudioManager shared] playSoundEffect:@"success"];
    } else {
        [ISLogger logError:@"Backup failed for %@: %@", filePath, *error ? (*error).localizedDescription : @"Unknown error"];
        [[ISAudioManager shared] playSoundEffect:@"error"];
    }
    
    return success;
}

- (NSArray *)getBackupsForFile:(NSString *)filePath {
    NSString *fileName = filePath.lastPathComponent;
    NSError *error = nil;
    NSArray *allBackups = [_fm contentsOfDirectoryAtPath:kBackupPath error:&error];
    
    if (error) {
        [ISLogger logError:@"Failed to read backups: %@", error.localizedDescription];
        return @[];
    }
    
    NSMutableArray *matchingBackups = [NSMutableArray array];
    for (NSString *backup in allBackups) {
        if ([backup containsString:fileName]) {
            NSString *fullPath = [kBackupPath stringByAppendingPathComponent:backup];
            NSDictionary *attrs = [_fm attributesOfItemAtPath:fullPath error:nil];
            
            NSMutableDictionary *backupInfo = [NSMutableDictionary dictionary];
            backupInfo[@"name"] = backup;
            backupInfo[@"path"] = fullPath;
            backupInfo[@"size"] = attrs[NSFileSize] ?: @0;
            backupInfo[@"modified"] = attrs[NSFileModificationDate] ?: [NSDate date];
            
            [matchingBackups addObject:backupInfo];
        }
    }
    
    [matchingBackups sortUsingComparator:^NSComparisonResult(NSDictionary *obj1, NSDictionary *obj2) {
        NSDate *date1 = obj1[@"modified"];
        NSDate *date2 = obj2[@"modified"];
        return [date2 compare:date1];
    }];
    
    return [matchingBackups copy];
}

- (BOOL)restoreBackup:(NSString *)backupPath toPath:(NSString *)destination error:(NSError **)error {
    if (![_fm fileExistsAtPath:backupPath]) {
        if (error) *error = [NSError errorWithDomain:@"ISFileManager" code:404 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Backup file not found"}];
        return NO;
    }
    
    if ([_fm fileExistsAtPath:destination]) {
        NSError *backupError = nil;
        if (![self backupFile:destination error:&backupError]) {
            [ISLogger logError:@"Failed to backup before restore: %@", backupError.localizedDescription];
        }
    }
    
    BOOL success = [_fm copyItemAtPath:backupPath toPath:destination error:error];
    
    if (success) {
        [ISLogger logFileOperation:@"Restored from backup" path:backupPath];
        
        if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"10.0")) {
            UINotificationFeedbackGenerator *generator = [[UINotificationFeedbackGenerator alloc] init];
            [generator notificationOccurred:UINotificationFeedbackTypeSuccess];
        }
        
        [[ISAudioManager shared] playSoundEffect:@"success"];
    }
    
    return success;
}

- (NSData *)readFileAtPath:(NSString *)path error:(NSError **)error {
    int fd = open([path UTF8String], O_RDONLY);
    if (fd == -1) {
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Failed to open file"}];
        return nil;
    }
    
    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Failed to stat file"}];
        return nil;
    }
    
    size_t size = (size_t)st.st_size;
    void *buffer = malloc(size);
    if (!buffer) {
        close(fd);
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:ENOMEM 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Out of memory"}];
        return nil;
    }
    
    ssize_t bytesRead = read(fd, buffer, size);
    close(fd);
    
    if (bytesRead != (ssize_t)size) {
        free(buffer);
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Failed to read entire file"}];
        return nil;
    }
    
    NSData *data = [NSData dataWithBytesNoCopy:buffer length:size freeWhenDone:YES];
    [ISLogger logFileOperation:@"File read" path:path];
    return data;
}

- (BOOL)writeData:(NSData *)data toPath:(NSString *)path error:(NSError **)error {
    NSString *tempDir = NSTemporaryDirectory();
    char tempTemplate[PATH_MAX];
    snprintf(tempTemplate, sizeof(tempTemplate), "%s/isavetool.XXXXXX", [tempDir UTF8String]);
    
    int fd = mkstemp(tempTemplate);
    if (fd == -1) {
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Failed to create temp file"}];
        return NO;
    }
    
    ssize_t bytesWritten = write(fd, data.bytes, data.length);
    if (bytesWritten != (ssize_t)data.length) {
        close(fd);
        unlink(tempTemplate);
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EIO 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Failed to write data"}];
        return NO;
    }
    
    fsync(fd);
    close(fd);
    
    NSString *tempPath = [NSString stringWithUTF8String:tempTemplate];
    BOOL success = [_fm moveItemAtPath:tempPath toPath:path error:error];
    
    if (success) {
        [ISLogger logFileOperation:@"File written" path:path];
        [[ISAudioManager shared] playSoundEffect:@"click"];
    } else {
        unlink(tempTemplate);
    }
    
    return success;
}

- (BOOL)isBinaryPlist:(NSData *)data {
    if (data.length < 8) return NO;
    const char *bytes = (const char *)data.bytes;
    return (strncmp(bytes, "bplist", 6) == 0);
}

- (id)parsePlistData:(NSData *)data error:(NSError **)error {
    if (!data || data.length == 0) {
        if (error) *error = [NSError errorWithDomain:@"ISPlistEditor" code:400 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Empty data"}];
        return nil;
    }
    
    id plist = nil;
    @try {
        plist = [NSPropertyListSerialization propertyListWithData:data
                                                          options:NSPropertyListMutableContainersAndLeaves
                                                           format:NULL
                                                            error:error];
    } @catch (NSException *exception) {
        if (error) {
            *error = [NSError errorWithDomain:@"ISPlistEditor" code:500 
                                      userInfo:@{NSLocalizedDescriptionKey: exception.reason ?: @"Unknown parsing error"}];
        }
    }
    
    return plist;
}

- (BOOL)savePlistObject:(id)object toPath:(NSString *)path binary:(BOOL)binary error:(NSError **)error {
    NSPropertyListFormat format = binary ? NSPropertyListBinaryFormat_v1_0 : NSPropertyListXMLFormat_v1_0;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:object
                                                              format:format
                                                             options:0
                                                               error:error];
    
    if (!data) {
        return NO;
    }
    
    return [self writeData:data toPath:path error:error];
}

- (BOOL)exportToHDD:(NSData *)data fileName:(NSString *)fileName error:(NSError **)error {
    NSString *hddPath = @"/var/mobile/Documents/Exports";
    
    if (![_fm fileExistsAtPath:hddPath]) {
        [_fm createDirectoryAtPath:hddPath withIntermediateDirectories:YES attributes:nil error:nil];
    }
    
    NSString *exportPath = [hddPath stringByAppendingPathComponent:fileName];
    return [data writeToFile:exportPath options:NSDataWritingAtomic error:error];
}

- (NSDictionary *)getFileInfo:(NSString *)path {
    NSDictionary *attrs = [_fm attributesOfItemAtPath:path error:nil];
    if (!attrs) return nil;
    
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    info[@"path"] = path;
    info[@"name"] = [path lastPathComponent];
    info[@"size"] = attrs[NSFileSize] ?: @0;
    info[@"modified"] = attrs[NSFileModificationDate] ?: [NSDate date];
    info[@"created"] = attrs[NSFileCreationDate] ?: [NSDate date];
    info[@"type"] = attrs[NSFileType];
    info[@"permissions"] = attrs[NSFilePosixPermissions] ?: @0755;
    
    // Get file extension and type
    NSString *extension = [path pathExtension].lowercaseString;
    info[@"extension"] = extension;
    
    NSArray *imageExtensions = @[@"png", @"jpg", @"jpeg", @"gif", @"bmp", @"tiff"];
    NSArray *plistExtensions = @[@"plist"];
    NSArray *archiveExtensions = @[@"zip", @"rar", @"7z", @"tar", @"gz"];
    NSArray *textExtensions = @[@"txt", @"xml", @"json", @"html", @"css", @"js"];
    NSArray *databaseExtensions = @[@"sqlite", @"db", @"sqlite3"];
    
    if ([imageExtensions containsObject:extension]) {
        info[@"fileType"] = @"Image";
    } else if ([plistExtensions containsObject:extension]) {
        info[@"fileType"] = @"Plist";
    } else if ([archiveExtensions containsObject:extension]) {
        info[@"fileType"] = @"Archive";
    } else if ([textExtensions containsObject:extension]) {
        info[@"fileType"] = @"Text";
    } else if ([databaseExtensions containsObject:extension]) {
        info[@"fileType"] = @"Database";
    } else if ([extension isEqualToString:@"mp3"] || [extension isEqualToString:@"wav"] || [extension isEqualToString:@"m4a"]) {
        info[@"fileType"] = @"Audio";
    } else if ([extension isEqualToString:@"mp4"] || [extension isEqualToString:@"mov"] || [extension isEqualToString:@"avi"]) {
        info[@"fileType"] = @"Video";
    } else {
        info[@"fileType"] = @"Unknown";
    }
    
    return [info copy];
}

- (long long)calculateFolderSize:(NSString *)path {
    __block long long totalSize = 0;
    
    @try {
        NSDirectoryEnumerator *enumerator = [_fm enumeratorAtPath:path];
        NSString *file;
        
        while ((file = [enumerator nextObject])) {
            NSString *fullPath = [path stringByAppendingPathComponent:file];
            NSDictionary *attrs = [_fm attributesOfItemAtPath:fullPath error:nil];
            
            if (attrs[NSFileType] == NSFileTypeRegular) {
                totalSize += [attrs[NSFileSize] longLongValue];
            }
        }
    } @catch (NSException *exception) {
        [ISLogger logError:@"Error calculating folder size: %@", exception.reason];
    }
    
    return totalSize;
}

- (NSArray *)searchFiles:(NSString *)searchText inPath:(NSString *)path {
    NSMutableArray *results = [NSMutableArray array];
    
    @try {
        NSDirectoryEnumerator *enumerator = [_fm enumeratorAtPath:path];
        NSString *file;
        
        while ((file = [enumerator nextObject])) {
            if ([file rangeOfString:searchText options:NSCaseInsensitiveSearch].location != NSNotFound) {
                NSString *fullPath = [path stringByAppendingPathComponent:file];
                NSDictionary *attrs = [_fm attributesOfItemAtPath:fullPath error:nil];
                
                if (attrs[NSFileType] == NSFileTypeRegular) {
                    NSMutableDictionary *fileInfo = [NSMutableDictionary dictionary];
                    fileInfo[@"name"] = file;
                    fileInfo[@"path"] = fullPath;
                    fileInfo[@"size"] = attrs[NSFileSize] ?: @0;
                    fileInfo[@"modified"] = attrs[NSFileModificationDate] ?: [NSDate date];
                    
                    [results addObject:fileInfo];
                }
            }
        }
    } @catch (NSException *exception) {
        [ISLogger logError:@"Error searching files: %@", exception.reason];
    }
    
    return [results copy];
}

- (NSArray *)getDuplicateFilesInPath:(NSString *)path {
    NSMutableDictionary *fileHashes = [NSMutableDictionary dictionary];
    NSMutableArray *duplicates = [NSMutableArray array];
    
    @try {
        NSDirectoryEnumerator *enumerator = [_fm enumeratorAtPath:path];
        NSString *file;
        
        while ((file = [enumerator nextObject])) {
            NSString *fullPath = [path stringByAppendingPathComponent:file];
            NSDictionary *attrs = [_fm attributesOfItemAtPath:fullPath error:nil];
            
            if (attrs[NSFileType] == NSFileTypeRegular) {
                NSString *checksum = [self getFileChecksum:fullPath algorithm:@"MD5"];
                if (checksum) {
                    if (fileHashes[checksum]) {
                        // Found duplicate
                        NSMutableArray *duplicateGroup = fileHashes[checksum];
                        [duplicateGroup addObject:fullPath];
                    } else {
                        fileHashes[checksum] = [NSMutableArray arrayWithObject:fullPath];
                    }
                }
            }
        }
        
        // Collect groups with more than one file
        for (NSString *hash in fileHashes.allKeys) {
            NSArray *group = fileHashes[hash];
            if (group.count > 1) {
                [duplicates addObject:group];
            }
        }
    } @catch (NSException *exception) {
        [ISLogger logError:@"Error finding duplicates: %@", exception.reason];
    }
    
    return [duplicates copy];
}

- (BOOL)compressFile:(NSString *)sourcePath toPath:(NSString *)destPath error:(NSError **)error {
    // Simple compression - just copy for now
    // In real implementation, use libz or other compression library
    return [_fm copyItemAtPath:sourcePath toPath:destPath error:error];
}

- (BOOL)decompressFile:(NSString *)sourcePath toPath:(NSString *)destPath error:(NSError **)error {
    // Simple decompression - just copy for now
    return [_fm copyItemAtPath:sourcePath toPath:destPath error:error];
}

- (NSString *)getFileChecksum:(NSString *)path algorithm:(NSString *)algorithm {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;
    
    return [ISEncryptionManager hashString:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] 
                                algorithm:algorithm];
}

- (BOOL)encryptFile:(NSString *)sourcePath toPath:(NSString *)destPath password:(NSString *)password error:(NSError **)error {
    NSData *fileData = [NSData dataWithContentsOfFile:sourcePath];
    if (!fileData) {
        if (error) *error = [NSError errorWithDomain:@"ISFileManager" code:404 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Source file not found"}];
        return NO;
    }
    
    NSData *encryptedData = [ISEncryptionManager encryptData:fileData password:password];
    if (!encryptedData) {
        if (error) *error = [NSError errorWithDomain:@"ISFileManager" code:500 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Encryption failed"}];
        return NO;
    }
    
    return [encryptedData writeToFile:destPath options:NSDataWritingAtomic error:error];
}

- (BOOL)decryptFile:(NSString *)sourcePath toPath:(NSString *)destPath password:(NSString *)password error:(NSError **)error {
    NSData *encryptedData = [NSData dataWithContentsOfFile:sourcePath];
    if (!encryptedData) {
        if (error) *error = [NSError errorWithDomain:@"ISFileManager" code:404 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Encrypted file not found"}];
        return NO;
    }
    
    NSData *decryptedData = [ISEncryptionManager decryptData:encryptedData password:password];
    if (!decryptedData) {
        if (error) *error = [NSError errorWithDomain:@"ISFileManager" code:500 
                                             userInfo:@{NSLocalizedDescriptionKey: @"Decryption failed - wrong password?"}];
        return NO;
    }
    
    return [decryptedData writeToFile:destPath options:NSDataWritingAtomic error:error];
}

- (NSArray *)batchOperation:(NSArray *)files operation:(NSString *)operation error:(NSError **)error {
    NSMutableArray *results = [NSMutableArray array];
    
    for (NSDictionary *fileInfo in files) {
        NSString *path = fileInfo[@"path"];
        NSError *opError = nil;
        BOOL success = NO;
        
        if ([operation isEqualToString:@"backup"]) {
            success = [self backupFile:path error:&opError];
        } else if ([operation isEqualToString:@"encrypt"]) {
            NSString *password = fileInfo[@"password"];
            NSString *destPath = [kEncryptedPath stringByAppendingPathComponent:[path lastPathComponent]];
            success = [self encryptFile:path toPath:destPath password:password error:&opError];
        }
        
        NSMutableDictionary *result = [NSMutableDictionary dictionary];
        result[@"file"] = path;
        result[@"success"] = @(success);
        if (opError) {
            result[@"error"] = opError.localizedDescription;
        }
        
        [results addObject:result];
    }
    
    return [results copy];
}
@end

// MARK: - Hex Viewer/Editor
@interface ISHexViewController : UIViewController <UITextViewDelegate>
@property (nonatomic, strong) NSData *fileData;
@property (nonatomic, strong) NSString *filePath;
@property (nonatomic, strong) UITextView *hexTextView;
@property (nonatomic, strong) UIScrollView *scrollView;
@property (nonatomic, strong) UILabel *offsetLabel;
@property (nonatomic, strong) UIBarButtonItem *editButton;
@property (nonatomic, assign) BOOL isEditing;
@end

@implementation ISHexViewController

- (instancetype)initWithData:(NSData *)data filePath:(NSString *)filePath {
    self = [super init];
    if (self) {
        _fileData = data;
        _filePath = filePath;
        _isEditing = NO;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.title = @"Binary Viewer";
    self.view.backgroundColor = [ISTheme hexViewBackground];
    
    [self setupNavigationBar];
    [self setupUI];
    [self displayHexData];
}

- (void)setupNavigationBar {
    self.editButton = [[UIBarButtonItem alloc] initWithTitle:@"Edit"
                                                       style:UIBarButtonItemStylePlain
                                                      target:self
                                                      action:@selector(toggleEditMode)];
    
    UIBarButtonItem *saveButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemSave
                                                                                target:self
                                                                                action:@selector(saveChanges)];
    saveButton.enabled = NO;
    
    UIBarButtonItem *toolsButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAction
                                                                                 target:self
                                                                                 action:@selector(showTools)];
    
    self.navigationItem.rightBarButtonItems = @[toolsButton, self.editButton, saveButton];
}

- (void)setupUI {
    self.scrollView = [[UIScrollView alloc] initWithFrame:self.view.bounds];
    self.scrollView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.scrollView.backgroundColor = [ISTheme hexViewBackground];
    [self.view addSubview:self.scrollView];
    
    self.offsetLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 10, self.view.bounds.size.width - 20, 20)];
    self.offsetLabel.textColor = [ISTheme hexOffsetColor];
    if (@available(iOS 13.0, *)) {
        self.offsetLabel.font = [UIFont monospacedDigitSystemFontOfSize:12 weight:UIFontWeightRegular];
    } else {
        self.offsetLabel.font = [UIFont fontWithName:@"Courier" size:12];
    }
    self.offsetLabel.text = @"Offset: 0x00000000";
    [self.scrollView addSubview:self.offsetLabel];
    
    CGFloat textViewY = self.offsetLabel.frame.origin.y + self.offsetLabel.frame.size.height + 10;
    self.hexTextView = [[UITextView alloc] initWithFrame:CGRectMake(10, textViewY, self.view.bounds.size.width - 20, self.view.bounds.size.height - textViewY - 20)];
    self.hexTextView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.hexTextView.backgroundColor = [ISTheme hexViewBackground];
    self.hexTextView.textColor = [ISTheme hexTextColor];
    
    if (@available(iOS 13.0, *)) {
        self.hexTextView.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    } else {
        self.hexTextView.font = [UIFont fontWithName:@"Courier" size:12];
    }
    
    self.hexTextView.editable = NO;
    self.hexTextView.delegate = self;
    self.hexTextView.autocorrectionType = UITextAutocorrectionTypeNo;
    self.hexTextView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.hexTextView.spellCheckingType = UITextSpellCheckingTypeNo;
    [self.scrollView addSubview:self.hexTextView];
}

- (void)displayHexData {
    NSMutableString *hexString = [NSMutableString string];
    NSMutableString *asciiString = [NSMutableString string];
    
    const unsigned char *bytes = (const unsigned char *)[self.fileData bytes];
    NSUInteger length = [self.fileData length];
    
    for (NSUInteger i = 0; i < length; i++) {
        [hexString appendFormat:@"%02X ", bytes[i]];
        
        if (bytes[i] >= 32 && bytes[i] <= 126) {
            [asciiString appendFormat:@"%c", bytes[i]];
        } else {
            [asciiString appendString:@"."];
        }
        
        if ((i + 1) % 16 == 0) {
            [hexString appendFormat:@"   %@\n", asciiString];
            [asciiString setString:@""];
        } else if ((i + 1) % 8 == 0) {
            [hexString appendString:@" "];
        }
    }
    
    if (asciiString.length > 0) {
        NSUInteger remaining = 16 - (length % 16);
        for (NSUInteger i = 0; i < remaining; i++) {
            [hexString appendString:@"   "];
            if ((i + length % 16 + 1) % 8 == 0) {
                [hexString appendString:@" "];
            }
        }
        [hexString appendFormat:@"   %@", asciiString];
    }
    
    NSMutableAttributedString *attributedString = [[NSMutableAttributedString alloc] initWithString:@""];
    
    for (NSUInteger offset = 0; offset < length; offset += 16) {
        NSString *offsetStr = [NSString stringWithFormat:@"0x%08lX: ", (unsigned long)offset];
        NSMutableAttributedString *line = [[NSMutableAttributedString alloc] initWithString:offsetStr];
        [line addAttribute:NSForegroundColorAttributeName 
                     value:[ISTheme hexOffsetColor] 
                     range:NSMakeRange(0, line.length)];
        
        NSUInteger lineLength = MIN(16, length - offset);
        NSMutableString *hexLine = [NSMutableString string];
        NSMutableString *asciiLine = [NSMutableString string];
        
        for (NSUInteger i = 0; i < lineLength; i++) {
            unsigned char byte = bytes[offset + i];
            [hexLine appendFormat:@"%02X ", byte];
            
            if (byte >= 32 && byte <= 126) {
                [asciiLine appendFormat:@"%c", byte];
            } else {
                [asciiLine appendString:@"."];
            }
            
            if (i == 7) {
                [hexLine appendString:@" "];
            }
        }
        
        if (lineLength < 16) {
            for (NSUInteger i = lineLength; i < 16; i++) {
                [hexLine appendString:@"   "];
                if (i == 7) {
                    [hexLine appendString:@" "];
                }
            }
        }
        
        [hexLine appendFormat:@"  %@", asciiLine];
        
        NSAttributedString *hexPart = [[NSAttributedString alloc] initWithString:hexLine
                                                                      attributes:@{
            NSForegroundColorAttributeName: [ISTheme hexTextColor]
        }];
        
        [line appendAttributedString:hexPart];
        [line appendAttributedString:[[NSAttributedString alloc] initWithString:@"\n"]];
        [attributedString appendAttributedString:line];
    }
    
    self.hexTextView.attributedText = attributedString;
    
    CGSize textSize = [self.hexTextView sizeThatFits:CGSizeMake(self.hexTextView.frame.size.width, CGFLOAT_MAX)];
    CGFloat newHeight = textSize.height;
    CGFloat maxHeight = self.view.bounds.size.height - self.hexTextView.frame.origin.y - 20;
    if (newHeight > maxHeight) {
        newHeight = maxHeight;
    }
    
    self.hexTextView.frame = CGRectMake(10, self.hexTextView.frame.origin.y, 
                                       self.view.bounds.size.width - 20, newHeight);
    
    CGFloat contentHeight = self.hexTextView.frame.origin.y + textSize.height + 20;
    self.scrollView.contentSize = CGSizeMake(self.view.bounds.size.width, contentHeight);
}

- (void)toggleEditMode {
    self.isEditing = !self.isEditing;
    self.hexTextView.editable = self.isEditing;
    self.editButton.title = self.isEditing ? @"Cancel" : @"Edit";
    
    UIBarButtonItem *saveButton = self.navigationItem.rightBarButtonItems[2];
    saveButton.enabled = self.isEditing;
    
    if (self.isEditing) {
        [self.hexTextView becomeFirstResponder];
    } else {
        [self.hexTextView resignFirstResponder];
        [self displayHexData];
    }
}

- (void)showTools {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Hex Tools"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Calculate Checksum"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self calculateChecksum];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Find Pattern"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self findPattern];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Export as C Array"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self exportAsCArray];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)calculateChecksum {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Checksum"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"MD5"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *checksum = [ISEncryptionManager hashString:[[NSString alloc] initWithData:self.fileData encoding:NSUTF8StringEncoding] 
                                                   algorithm:@"MD5"];
        [self showAlertWithTitle:@"MD5 Checksum" message:checksum];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"SHA1"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *checksum = [ISEncryptionManager hashString:[[NSString alloc] initWithData:self.fileData encoding:NSUTF8StringEncoding] 
                                                   algorithm:@"SHA1"];
        [self showAlertWithTitle:@"SHA1 Checksum" message:checksum];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"SHA256"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *checksum = [ISEncryptionManager hashString:[[NSString alloc] initWithData:self.fileData encoding:NSUTF8StringEncoding] 
                                                   algorithm:@"SHA256"];
        [self showAlertWithTitle:@"SHA256 Checksum" message:checksum];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)findPattern {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Find Pattern"
                                                                   message:@"Enter hex pattern (e.g., DEADBEEF):"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Hex pattern";
        textField.keyboardType = UIKeyboardTypeASCIICapable;
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Find"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *pattern = alert.textFields.firstObject.text;
        [self searchForPattern:pattern];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)searchForPattern:(NSString *)pattern {
    pattern = [pattern stringByReplacingOccurrencesOfString:@" " withString:@""];
    if (pattern.length % 2 != 0) {
        [self showAlertWithTitle:@"Error" message:@"Hex pattern must have even length"];
        return;
    }
    
    NSMutableData *patternData = [NSMutableData data];
    for (int i = 0; i < pattern.length; i += 2) {
        NSString *byteString = [pattern substringWithRange:NSMakeRange(i, 2)];
        NSScanner *scanner = [NSScanner scannerWithString:byteString];
        unsigned int byte;
        [scanner scanHexInt:&byte];
        [patternData appendBytes:&byte length:1];
    }
    
    NSData *searchData = self.fileData;
    const void *bytes = searchData.bytes;
    const void *patternBytes = patternData.bytes;
    NSUInteger patternLength = patternData.length;
    
    NSMutableArray *positions = [NSMutableArray array];
    
    for (NSUInteger i = 0; i <= searchData.length - patternLength; i++) {
        if (memcmp(bytes + i, patternBytes, patternLength) == 0) {
            [positions addObject:@(i)];
        }
    }
    
    if (positions.count > 0) {
        NSString *message = [NSString stringWithFormat:@"Found %lu matches:\n%@", 
                            (unsigned long)positions.count,
                            [positions componentsJoinedByString:@", "]];
        [self showAlertWithTitle:@"Pattern Found" message:message];
    } else {
        [self showAlertWithTitle:@"Not Found" message:@"Pattern not found in file"];
    }
}

- (void)exportAsCArray {
    NSMutableString *cArray = [NSMutableString stringWithString:@"const unsigned char data[] = {\n"];
    
    const unsigned char *bytes = (const unsigned char *)[self.fileData bytes];
    NSUInteger length = [self.fileData length];
    
    for (NSUInteger i = 0; i < length; i++) {
        [cArray appendFormat:@"0x%02X", bytes[i]];
        if (i < length - 1) {
            [cArray appendString:@", "];
        }
        if ((i + 1) % 16 == 0) {
            [cArray appendString:@"\n"];
        }
    }
    
    [cArray appendString:@"\n};\n"];
    [cArray appendFormat:@"const unsigned int data_len = %lu;\n", (unsigned long)length];
    
    UIActivityViewController *activityVC = [[UIActivityViewController alloc] initWithActivityItems:@[cArray]
                                                                             applicationActivities:nil];
    [self presentViewController:activityVC animated:YES completion:nil];
}

- (void)saveChanges {
    NSString *hexText = self.hexTextView.text;
    NSArray *lines = [hexText componentsSeparatedByString:@"\n"];
    NSMutableData *newData = [NSMutableData data];
    
    for (NSString *line in lines) {
        if (line.length < 10) continue;
        
        NSArray *components = [line componentsSeparatedByString:@":"];
        if (components.count < 2) continue;
        
        NSString *hexPart = components[1];
        NSArray *hexBytes = [hexPart componentsSeparatedByString:@" "];
        
        for (NSString *hexByte in hexBytes) {
            if (hexByte.length == 2) {
                NSScanner *scanner = [NSScanner scannerWithString:hexByte];
                unsigned int byte;
                if ([scanner scanHexInt:&byte]) {
                    [newData appendBytes:&byte length:1];
                }
            }
        }
    }
    
    NSError *error = nil;
    if ([[ISFileManager shared] writeData:newData toPath:self.filePath error:&error]) {
        self.fileData = newData;
        [self toggleEditMode];
        [self showAlertWithTitle:@"Success" message:@"File saved successfully"];
    } else {
        [self showAlertWithTitle:@"Error" message:error.localizedDescription ?: @"Failed to save file"];
    }
}

- (void)showAlertWithTitle:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}
@end

// MARK: - Plist Editor
@interface ISPlistEditorViewController : UIViewController <UITextViewDelegate>
@property (nonatomic, strong) id plistObject;
@property (nonatomic, strong) NSString *filePath;
@property (nonatomic, strong) UITextView *textView;
@property (nonatomic, assign) BOOL isBinaryPlist;
@property (nonatomic, strong) UISegmentedControl *formatControl;
@end

@implementation ISPlistEditorViewController

- (instancetype)initWithPlistObject:(id)plistObject filePath:(NSString *)filePath isBinary:(BOOL)isBinary {
    self = [super init];
    if (self) {
        _plistObject = plistObject;
        _filePath = filePath;
        _isBinaryPlist = isBinary;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.title = @"Plist Editor";
    self.view.backgroundColor = [ISTheme primaryBackground];
    
    [self setupNavigationBar];
    [self setupUI];
    [self displayPlistContent];
}

- (void)setupNavigationBar {
    UIBarButtonItem *saveButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemSave
                                                                                target:self
                                                                                action:@selector(savePlist)];
    
    UIBarButtonItem *binaryButton = [[UIBarButtonItem alloc] initWithTitle:self.isBinaryPlist ? @"Binary" : @"XML"
                                                                     style:UIBarButtonItemStylePlain
                                                                    target:self
                                                                    action:@selector(toggleFormat)];
    
    UIBarButtonItem *toolsButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAction
                                                                                 target:self
                                                                                 action:@selector(showTools)];
    
    self.navigationItem.rightBarButtonItems = @[toolsButton, saveButton, binaryButton];
}

- (void)setupUI {
    self.formatControl = [[UISegmentedControl alloc] initWithItems:@[@"Tree View", @"Raw XML", @"JSON"]];
    self.formatControl.selectedSegmentIndex = 0;
    self.formatControl.tintColor = [ISTheme accentColor];
    self.formatControl.frame = CGRectMake(10, 10, self.view.bounds.size.width - 20, 32);
    [self.formatControl addTarget:self action:@selector(formatChanged:) forControlEvents:UIControlEventValueChanged];
    [self.view addSubview:self.formatControl];
    
    CGFloat textViewY = self.formatControl.frame.origin.y + self.formatControl.frame.size.height + 10;
    self.textView = [[UITextView alloc] initWithFrame:CGRectMake(10, textViewY, 
                                                                self.view.bounds.size.width - 20, 
                                                                self.view.bounds.size.height - textViewY - 10)];
    self.textView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.textView.backgroundColor = [ISTheme secondaryBackground];
    self.textView.textColor = [ISTheme textPrimary];
    
    if (@available(iOS 13.0, *)) {
        self.textView.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    } else {
        self.textView.font = [UIFont fontWithName:@"Courier" size:12];
    }
    
    self.textView.delegate = self;
    self.textView.autocorrectionType = UITextAutocorrectionTypeNo;
    self.textView.autocapitalizationType = UITextAutocapitalizationTypeNone;
    self.textView.spellCheckingType = UITextSpellCheckingTypeNo;
    [self.view addSubview:self.textView];
}

- (void)displayPlistContent {
    if (self.formatControl.selectedSegmentIndex == 0) {
        // Tree View
        self.textView.text = [self stringFromPlistObject:self.plistObject indent:0];
    } else if (self.formatControl.selectedSegmentIndex == 1) {
        // Raw XML
        NSError *error = nil;
        NSData *xmlData = [NSPropertyListSerialization dataWithPropertyList:self.plistObject
                                                                     format:NSPropertyListXMLFormat_v1_0
                                                                    options:0
                                                                      error:&error];
        if (!error && xmlData) {
            NSString *xmlString = [[NSString alloc] initWithData:xmlData encoding:NSUTF8StringEncoding];
            self.textView.text = xmlString;
        } else {
            self.textView.text = [NSString stringWithFormat:@"Error: %@", error.localizedDescription];
        }
    } else {
        // JSON
        NSError *error = nil;
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:self.plistObject
                                                           options:NSJSONWritingPrettyPrinted
                                                             error:&error];
        if (!error && jsonData) {
            NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            self.textView.text = jsonString;
        } else {
            self.textView.text = [NSString stringWithFormat:@"Error converting to JSON: %@", error.localizedDescription];
        }
    }
}

- (NSString *)stringFromPlistObject:(id)object indent:(NSUInteger)indent {
    NSMutableString *result = [NSMutableString string];
    NSString *indentString = [@"" stringByPaddingToLength:indent * 4 withString:@" " startingAtIndex:0];
    
    if ([object isKindOfClass:[NSDictionary class]]) {
        [result appendString:@"{\n"];
        NSDictionary *dict = (NSDictionary *)object;
        NSArray *keys = [dict.allKeys sortedArrayUsingSelector:@selector(compare:)];
        
        for (NSString *key in keys) {
            id value = dict[key];
            [result appendFormat:@"%@    %@ = %@;\n", indentString, key, [self stringFromPlistObject:value indent:indent + 1]];
        }
        
        [result appendFormat:@"%@}", indentString];
        
    } else if ([object isKindOfClass:[NSArray class]]) {
        [result appendString:@"(\n"];
        NSArray *array = (NSArray *)object;
        
        for (id item in array) {
            [result appendFormat:@"%@    %@,\n", indentString, [self stringFromPlistObject:item indent:indent + 1]];
        }
        
        if (array.count > 0) {
            [result deleteCharactersInRange:NSMakeRange(result.length - 2, 1)];
        }
        
        [result appendFormat:@"%@)", indentString];
        
    } else if ([object isKindOfClass:[NSString class]]) {
        [result appendFormat:@"\"%@\"", object];
        
    } else if ([object isKindOfClass:[NSNumber class]]) {
        NSNumber *number = (NSNumber *)object;
        
        const char *objCType = [number objCType];
        if (strcmp(objCType, @encode(BOOL)) == 0) {
            [result appendString:[number boolValue] ? @"YES" : @"NO"];
        } else if (strcmp(objCType, @encode(int)) == 0 || 
                  strcmp(objCType, @encode(long)) == 0 ||
                  strcmp(objCType, @encode(long long)) == 0) {
            [result appendFormat:@"%lld", [number longLongValue]];
        } else if (strcmp(objCType, @encode(float)) == 0 ||
                  strcmp(objCType, @encode(double)) == 0) {
            [result appendFormat:@"%f", [number doubleValue]];
        } else {
            [result appendString:[number stringValue]];
        }
        
    } else if ([object isKindOfClass:[NSDate class]]) {
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        [formatter setDateFormat:@"yyyy-MM-dd HH:mm:ss Z"];
        [result appendFormat:@"<Date: %@>", [formatter stringFromDate:object]];
        
    } else if ([object isKindOfClass:[NSData class]]) {
        NSData *data = (NSData *)object;
        [result appendFormat:@"<Data: %lu bytes>", (unsigned long)data.length];
        
    } else {
        [result appendFormat:@"<%@>", [object class]];
    }
    
    return result;
}

- (void)formatChanged:(UISegmentedControl *)sender {
    [self displayPlistContent];
}

- (void)showTools {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Plist Tools"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Validate Syntax"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self validateSyntax];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Minify"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self minifyPlist];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Convert Format"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self convertFormat];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)validateSyntax {
    NSString *content = self.textView.text;
    NSError *error = nil;
    
    if (self.formatControl.selectedSegmentIndex == 1) {
        // XML
        NSData *xmlData = [content dataUsingEncoding:NSUTF8StringEncoding];
        [NSPropertyListSerialization propertyListWithData:xmlData
                                                  options:0
                                                   format:NULL
                                                    error:&error];
    } else if (self.formatControl.selectedSegmentIndex == 2) {
        // JSON
        NSData *jsonData = [content dataUsingEncoding:NSUTF8StringEncoding];
        [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&error];
    }
    
    if (error) {
        [self showAlertWithTitle:@"Syntax Error" message:error.localizedDescription];
    } else {
        [self showAlertWithTitle:@"Success" message:@"Syntax is valid"];
    }
}

- (void)minifyPlist {
    NSString *content = self.textView.text;
    
    if (self.formatControl.selectedSegmentIndex == 2) {
        // JSON minify
        NSData *jsonData = [content dataUsingEncoding:NSUTF8StringEncoding];
        NSError *error = nil;
        id jsonObject = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&error];
        
        if (!error) {
            NSData *minifiedData = [NSJSONSerialization dataWithJSONObject:jsonObject options:0 error:&error];
            if (!error) {
                self.textView.text = [[NSString alloc] initWithData:minifiedData encoding:NSUTF8StringEncoding];
            }
        }
    } else {
        // Remove whitespace for XML/tree view
        content = [content stringByReplacingOccurrencesOfString:@"\\s+" withString:@" " options:NSRegularExpressionSearch range:NSMakeRange(0, content.length)];
        self.textView.text = content;
    }
}

- (void)convertFormat {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Convert To"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"XML Plist"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self convertToFormat:0];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"JSON"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self convertToFormat:1];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Tree View"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self convertToFormat:2];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)convertToFormat:(NSInteger)format {
    NSString *content = self.textView.text;
    NSError *error = nil;
    id parsedObject = nil;
    
    // Parse current content
    if (self.formatControl.selectedSegmentIndex == 1) {
        // From XML
        NSData *xmlData = [content dataUsingEncoding:NSUTF8StringEncoding];
        parsedObject = [NSPropertyListSerialization propertyListWithData:xmlData
                                                                 options:NSPropertyListMutableContainersAndLeaves
                                                                  format:NULL
                                                                   error:&error];
    } else if (self.formatControl.selectedSegmentIndex == 2) {
        // From JSON
        NSData *jsonData = [content dataUsingEncoding:NSUTF8StringEncoding];
        parsedObject = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingMutableContainers error:&error];
    }
    
    if (error) {
        [self showAlertWithTitle:@"Conversion Error" message:error.localizedDescription];
        return;
    }
    
    // Convert to new format
    if (format == 0) {
        // To XML
        NSData *xmlData = [NSPropertyListSerialization dataWithPropertyList:parsedObject
                                                                     format:NSPropertyListXMLFormat_v1_0
                                                                    options:0
                                                                      error:&error];
        if (!error) {
            self.textView.text = [[NSString alloc] initWithData:xmlData encoding:NSUTF8StringEncoding];
            self.formatControl.selectedSegmentIndex = 1;
        }
    } else if (format == 1) {
        // To JSON
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:parsedObject
                                                           options:NSJSONWritingPrettyPrinted
                                                             error:&error];
        if (!error) {
            self.textView.text = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
            self.formatControl.selectedSegmentIndex = 2;
        }
    } else if (format == 2) {
        // To Tree View
        self.plistObject = parsedObject;
        self.textView.text = [self stringFromPlistObject:parsedObject indent:0];
        self.formatControl.selectedSegmentIndex = 0;
    }
    
    if (error) {
        [self showAlertWithTitle:@"Error" message:error.localizedDescription];
    }
}

- (void)toggleFormat {
    self.isBinaryPlist = !self.isBinaryPlist;
    
    UIBarButtonItem *binaryButton = self.navigationItem.rightBarButtonItems[2];
    binaryButton.title = self.isBinaryPlist ? @"Binary" : @"XML";
    
    [self showAlertWithTitle:@"Format Changed" 
                     message:self.isBinaryPlist ? @"File will be saved as Binary plist" : @"File will be saved as XML plist"];
}

- (void)savePlist {
    if (self.formatControl.selectedSegmentIndex == 0) {
        [self showAlertWithTitle:@"Info" message:@"Tree view editing requires a proper parser. Use Raw XML for editing."];
        return;
    }
    
    NSString *content = self.textView.text;
    NSData *data = [content dataUsingEncoding:NSUTF8StringEncoding];
    
    NSError *error = nil;
    id parsedPlist = nil;
    
    if (self.formatControl.selectedSegmentIndex == 1) {
        // Parse XML
        parsedPlist = [NSPropertyListSerialization propertyListWithData:data
                                                                options:NSPropertyListMutableContainersAndLeaves
                                                                 format:NULL
                                                                  error:&error];
    } else if (self.formatControl.selectedSegmentIndex == 2) {
        // Parse JSON
        parsedPlist = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&error];
    }
    
    if (error) {
        [self showAlertWithTitle:@"Parse Error" message:error.localizedDescription];
        return;
    }
    
    if ([[ISFileManager shared] savePlistObject:parsedPlist 
                                         toPath:self.filePath 
                                         binary:self.isBinaryPlist 
                                          error:&error]) {
        self.plistObject = parsedPlist;
        [self showAlertWithTitle:@"Success" message:@"Plist saved successfully"];
    } else {
        [self showAlertWithTitle:@"Error" message:error.localizedDescription ?: @"Failed to save plist"];
    }
}

- (void)showAlertWithTitle:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}
@end

// MARK: - SQLite Browser
@interface ISSQLiteBrowser : UIViewController <UITableViewDelegate, UITableViewDataSource>
@property (nonatomic, strong) NSString *databasePath;
@property (nonatomic, assign) sqlite3 *database;
@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) NSArray *tables;
@property (nonatomic, strong) NSArray *currentData;
@property (nonatomic, strong) NSString *currentTable;
@property (nonatomic, strong) UIActivityIndicatorView *loadingIndicator;
@end

@implementation ISSQLiteBrowser

- (instancetype)initWithDatabasePath:(NSString *)path {
    self = [super init];
    if (self) {
        _databasePath = path;
        _database = NULL;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.title = @"SQLite Browser";
    self.view.backgroundColor = [ISTheme primaryBackground];
    
    [self setupNavigationBar];
    [self setupUI];
    [self openDatabase];
}

- (void)setupNavigationBar {
    UIBarButtonItem *refreshButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                                                   target:self
                                                                                   action:@selector(refreshDatabase)];
    
    UIBarButtonItem *queryButton = [[UIBarButtonItem alloc] initWithTitle:@"Query"
                                                                    style:UIBarButtonItemStylePlain
                                                                   target:self
                                                                   action:@selector(runQuery)];
    
    self.navigationItem.rightBarButtonItems = @[refreshButton, queryButton];
}

- (void)setupUI {
    self.tableView = [[UITableView alloc] initWithFrame:self.view.bounds style:UITableViewStylePlain];
    self.tableView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.tableView.delegate = self;
    self.tableView.dataSource = self;
    self.tableView.backgroundColor = [UIColor clearColor];
    [self.tableView registerClass:[UITableViewCell class] forCellReuseIdentifier:@"Cell"];
    [self.view addSubview:self.tableView];
    
    self.loadingIndicator = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
    self.loadingIndicator.color = [ISTheme accentColor];
    self.loadingIndicator.center = self.view.center;
    self.loadingIndicator.hidesWhenStopped = YES;
    [self.view addSubview:self.loadingIndicator];
}

- (void)openDatabase {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int result = sqlite3_open([self.databasePath UTF8String], &self->_database);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            if (result != SQLITE_OK) {
                [self showAlertWithTitle:@"Error" 
                                 message:[NSString stringWithFormat:@"Failed to open database: %s", sqlite3_errmsg(self.database)]];
                return;
            }
            
            [self loadTables];
        });
    });
}

- (void)loadTables {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSMutableArray *tables = [NSMutableArray array];
        sqlite3_stmt *statement;
        
        const char *query = "SELECT name FROM sqlite_master WHERE type='table'";
        
        if (sqlite3_prepare_v2(self.database, query, -1, &statement, NULL) == SQLITE_OK) {
            while (sqlite3_step(statement) == SQLITE_ROW) {
                const char *tableName = (const char *)sqlite3_column_text(statement, 0);
                if (tableName) {
                    [tables addObject:[NSString stringWithUTF8String:tableName]];
                }
            }
            sqlite3_finalize(statement);
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            self.tables = [tables copy];
            [self.tableView reloadData];
        });
    });
}

- (void)loadTableData:(NSString *)tableName {
    [self.loadingIndicator startAnimating];
    self.currentTable = tableName;
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSMutableArray *data = [NSMutableArray array];
        sqlite3_stmt *statement;
        
        NSString *query = [NSString stringWithFormat:@"SELECT * FROM %@ LIMIT 100", tableName];
        
        if (sqlite3_prepare_v2(self.database, [query UTF8String], -1, &statement, NULL) == SQLITE_OK) {
            int columnCount = sqlite3_column_count(statement);
            
            // Get column names
            NSMutableArray *columns = [NSMutableArray array];
            for (int i = 0; i < columnCount; i++) {
                const char *columnName = sqlite3_column_name(statement, i);
                [columns addObject:[NSString stringWithUTF8String:columnName]];
            }
            [data addObject:columns];
            
            // Get rows
            while (sqlite3_step(statement) == SQLITE_ROW) {
                NSMutableArray *row = [NSMutableArray array];
                for (int i = 0; i < columnCount; i++) {
                    const char *value = (const char *)sqlite3_column_text(statement, i);
                    if (value) {
                        [row addObject:[NSString stringWithUTF8String:value]];
                    } else {
                        [row addObject:@"(null)"];
                    }
                }
                [data addObject:row];
            }
            sqlite3_finalize(statement);
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            self.currentData = [data copy];
            [self.tableView reloadData];
        });
    });
}

- (void)refreshDatabase {
    [self loadTables];
    self.currentData = nil;
    self.currentTable = nil;
}

- (void)runQuery {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Run SQL Query"
                                                                   message:@"Enter SQL query:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"SELECT * FROM table";
        if (self.currentTable) {
            textField.text = [NSString stringWithFormat:@"SELECT * FROM %@", self.currentTable];
        }
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Run"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *query = alert.textFields.firstObject.text;
        [self executeQuery:query];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)executeQuery:(NSString *)query {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSMutableArray *data = [NSMutableArray array];
        sqlite3_stmt *statement;
        
        if (sqlite3_prepare_v2(self.database, [query UTF8String], -1, &statement, NULL) == SQLITE_OK) {
            int columnCount = sqlite3_column_count(statement);
            
            // Get column names
            NSMutableArray *columns = [NSMutableArray array];
            for (int i = 0; i < columnCount; i++) {
                const char *columnName = sqlite3_column_name(statement, i);
                [columns addObject:[NSString stringWithUTF8String:columnName]];
            }
            [data addObject:columns];
            
            // Get rows
            while (sqlite3_step(statement) == SQLITE_ROW) {
                NSMutableArray *row = [NSMutableArray array];
                for (int i = 0; i < columnCount; i++) {
                    const char *value = (const char *)sqlite3_column_text(statement, i);
                    if (value) {
                        [row addObject:[NSString stringWithUTF8String:value]];
                    } else {
                        [row addObject:@"(null)"];
                    }
                }
                [data addObject:row];
            }
            sqlite3_finalize(statement);
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            self.currentData = [data copy];
            self.currentTable = nil;
            [self.tableView reloadData];
        });
    });
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    if (self.currentData) {
        return self.currentData.count;
    } else {
        return self.tables.count;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"Cell" forIndexPath:indexPath];
    cell.backgroundColor = [UIColor clearColor];
    cell.textLabel.textColor = [ISTheme textPrimary];
    
    if (self.currentData) {
        if (indexPath.row == 0) {
            // Header row
            NSArray *columns = self.currentData[indexPath.row];
            cell.textLabel.text = [columns componentsJoinedByString:@" | "];
            cell.textLabel.font = [UIFont boldSystemFontOfSize:12];
            cell.backgroundColor = [ISTheme secondaryBackground];
        } else {
            NSArray *row = self.currentData[indexPath.row];
            cell.textLabel.text = [row componentsJoinedByString:@" | "];
            cell.textLabel.font = [UIFont systemFontOfSize:12];
            cell.textLabel.numberOfLines = 0;
        }
    } else {
        cell.textLabel.text = self.tables[indexPath.row];
        cell.textLabel.font = [UIFont systemFontOfSize:16];
    }
    
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    
    if (!self.currentData) {
        NSString *tableName = self.tables[indexPath.row];
        [self loadTableData:tableName];
    }
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    if (self.currentData && indexPath.row > 0) {
        return 60;
    }
    return 44;
}

- (void)showAlertWithTitle:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)dealloc {
    if (_database) {
        sqlite3_close(_database);
    }
}
@end

// MARK: - Image Viewer
@interface ISImageViewer : UIViewController <UIScrollViewDelegate>
@property (nonatomic, strong) UIImage *image;
@property (nonatomic, strong) UIImageView *imageView;
@property (nonatomic, strong) UIScrollView *scrollView;
@end

@implementation ISImageViewer

- (instancetype)initWithImage:(UIImage *)image {
    self = [super init];
    if (self) {
        _image = image;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.title = @"Image Viewer";
    self.view.backgroundColor = [UIColor blackColor];
    
    [self setupUI];
}

- (void)setupUI {
    self.scrollView = [[UIScrollView alloc] initWithFrame:self.view.bounds];
    self.scrollView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.scrollView.delegate = self;
    self.scrollView.minimumZoomScale = 1.0;
    self.scrollView.maximumZoomScale = 4.0;
    [self.view addSubview:self.scrollView];
    
    self.imageView = [[UIImageView alloc] initWithImage:self.image];
    self.imageView.contentMode = UIViewContentModeScaleAspectFit;
    self.imageView.frame = self.scrollView.bounds;
    self.imageView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.scrollView addSubview:self.imageView];
    
    // Add tap to dismiss
    UITapGestureRecognizer *tapGesture = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(handleTap:)];
    [self.view addGestureRecognizer:tapGesture];
    
    // Add double tap to zoom
    UITapGestureRecognizer *doubleTapGesture = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(handleDoubleTap:)];
    doubleTapGesture.numberOfTapsRequired = 2;
    [self.view addGestureRecognizer:doubleTapGesture];
    
    [tapGesture requireGestureRecognizerToFail:doubleTapGesture];
}

- (UIView *)viewForZoomingInScrollView:(UIScrollView *)scrollView {
    return self.imageView;
}

- (void)handleTap:(UITapGestureRecognizer *)gesture {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)handleDoubleTap:(UITapGestureRecognizer *)gesture {
    if (self.scrollView.zoomScale > self.scrollView.minimumZoomScale) {
        [self.scrollView setZoomScale:self.scrollView.minimumZoomScale animated:YES];
    } else {
        CGPoint point = [gesture locationInView:self.imageView];
        CGRect zoomRect = CGRectMake(point.x - 50, point.y - 50, 100, 100);
        [self.scrollView zoomToRect:zoomRect animated:YES];
    }
}
@end

// MARK: - WebDAV Server
@interface ISWebDAVServer : NSObject
+ (instancetype)shared;
- (BOOL)startServerOnPort:(int)port;
- (void)stopServer;
- (BOOL)isRunning;
- (NSString *)serverURL;
@end

@implementation ISWebDAVServer {
    int _serverSocket;
    BOOL _isRunning;
    int _port;
}

+ (instancetype)shared {
    static ISWebDAVServer *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[ISWebDAVServer alloc] init];
    });
    return shared;
}

- (BOOL)startServerOnPort:(int)port {
    if (_isRunning) {
        [self stopServer];
    }
    
    _serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (_serverSocket < 0) {
        [ISLogger logError:@"Failed to create socket"];
        return NO;
    }
    
    int opt = 1;
    if (setsockopt(_serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        [ISLogger logError:@"Failed to set socket options"];
        close(_serverSocket);
        return NO;
    }
    
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);
    
    if (bind(_serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        [ISLogger logError:@"Failed to bind socket"];
        close(_serverSocket);
        return NO;
    }
    
    if (listen(_serverSocket, 5) < 0) {
        [ISLogger logError:@"Failed to listen on socket"];
        close(_serverSocket);
        return NO;
    }
    
    _port = port;
    _isRunning = YES;
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self acceptConnections];
    });
    
    [ISLogger log:@"WebDAV server started on port %d", port];
    return YES;
}

- (void)acceptConnections {
    while (_isRunning) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        
        int clientSocket = accept(_serverSocket, (struct sockaddr *)&clientAddr, &clientLen);
        if (clientSocket < 0) {
            if (_isRunning) {
                [ISLogger logError:@"Failed to accept connection"];
            }
            continue;
        }
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [self handleClient:clientSocket];
        });
    }
}

- (void)handleClient:(int)clientSocket {
    char buffer[4096];
    ssize_t bytesRead = read(clientSocket, buffer, sizeof(buffer) - 1);
    
    if (bytesRead > 0) {
        buffer[bytesRead] = '\0';
        NSString *request = [NSString stringWithUTF8String:buffer];
        
        // Simple HTTP response
        NSString *response = @"HTTP/1.1 200 OK\r\n"
                             @"Content-Type: text/html\r\n"
                             @"\r\n"
                             @"<html><body><h1>iSaveTool WebDAV Server</h1>"
                             @"<p>Server is running on port %d</p>"
                             @"<p>Use WebDAV client to connect</p></body></html>";
        
        NSString *fullResponse = [NSString stringWithFormat:response, _port];
        write(clientSocket, [fullResponse UTF8String], [fullResponse length]);
    }
    
    close(clientSocket);
}

- (void)stopServer {
    _isRunning = NO;
    if (_serverSocket >= 0) {
        close(_serverSocket);
        _serverSocket = -1;
    }
    [ISLogger log:@"WebDAV server stopped"];
}

- (BOOL)isRunning {
    return _isRunning;
}

- (NSString *)serverURL {
    NSString *ipAddress = [self getIPAddress];
    if (ipAddress) {
        return [NSString stringWithFormat:@"http://%@:%d", ipAddress, _port];
    }
    return [NSString stringWithFormat:@"http://localhost:%d", _port];
}

- (NSString *)getIPAddress {
    NSString *address = nil;
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    
    success = getifaddrs(&interfaces);
    if (success == 0) {
        temp_addr = interfaces;
        while (temp_addr != NULL) {
            if (temp_addr->ifa_addr->sa_family == AF_INET) {
                if ([[NSString stringWithUTF8String:temp_addr->ifa_name] isEqualToString:@"en0"]) {
                    address = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)];
                }
            }
            temp_addr = temp_addr->ifa_next;
        }
    }
    
    freeifaddrs(interfaces);
    return address;
}
@end

// MARK: - Game Save Manager
@interface ISGameSaveManager : NSObject
+ (instancetype)shared;
- (NSArray *)scanForGameSaves;
- (BOOL)backupGameSave:(NSString *)savePath slot:(int)slot;
- (BOOL)restoreGameSave:(NSString *)savePath slot:(int)slot;
- (NSArray *)getSaveSlotsForGame:(NSString *)gameName;
- (BOOL)validateSaveFile:(NSString *)savePath;
@end

@implementation ISGameSaveManager

+ (instancetype)shared {
    static ISGameSaveManager *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[ISGameSaveManager alloc] init];
    });
    return shared;
}

- (NSArray *)scanForGameSaves {
    NSMutableArray *gameSaves = [NSMutableArray array];
    
    // Scan common game directories
    NSArray *paths = @[
        @"/var/mobile/Documents",
        @"/var/mobile/Library",
        @"/var/mobile/Containers/Data/Application"
    ];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    
    for (NSString *path in paths) {
        @try {
            NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:path];
            NSString *file;
            
            while ((file = [enumerator nextObject])) {
                NSString *extension = file.pathExtension.lowercaseString;
                NSArray *saveExtensions = @[@"sav", @"save", @"dat", @"game", @"slot", @"bin"];
                
                if ([saveExtensions containsObject:extension]) {
                    NSString *fullPath = [path stringByAppendingPathComponent:file];
                    NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil];
                    
                    NSMutableDictionary *saveInfo = [NSMutableDictionary dictionary];
                    saveInfo[@"name"] = file.lastPathComponent;
                    saveInfo[@"path"] = fullPath;
                    saveInfo[@"size"] = attrs[NSFileSize] ?: @0;
                    saveInfo[@"modified"] = attrs[NSFileModificationDate] ?: [NSDate date];
                    saveInfo[@"gameName"] = [self guessGameNameFromPath:fullPath];
                    
                    [gameSaves addObject:saveInfo];
                }
            }
        } @catch (NSException *exception) {
            [ISLogger logError:@"Error scanning for game saves: %@", exception.reason];
        }
    }
    
    return [gameSaves copy];
}

- (NSString *)guessGameNameFromPath:(NSString *)path {
    // Extract game name from path
    NSArray *components = [path componentsSeparatedByString:@"/"];
    
    for (NSString *component in components) {
        if ([component hasPrefix:@"com."]) {
            // Probably a bundle ID
            NSArray *bundleParts = [component componentsSeparatedByString:@"."];
            if (bundleParts.count > 0) {
                NSString *lastPart = bundleParts.lastObject;
                if (lastPart.length > 0) {
                    return [[lastPart substringToIndex:1].uppercaseString stringByAppendingString:[lastPart substringFromIndex:1]];
                }
            }
            return component;
        }
    }
    
    return @"Unknown Game";
}

- (BOOL)backupGameSave:(NSString *)savePath slot:(int)slot {
    NSString *backupDir = [NSString stringWithFormat:@"%@/game_saves", kBackupPath];
    NSFileManager *fm = [NSFileManager defaultManager];
    
    if (![fm fileExistsAtPath:backupDir]) {
        [fm createDirectoryAtPath:backupDir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    
    NSString *gameName = [self guessGameNameFromPath:savePath];
    NSString *backupName = [NSString stringWithFormat:@"%@_slot%d_%@.save", 
                           gameName, slot, 
                           [[NSUUID UUID] UUIDString]];
    NSString *backupPath = [backupDir stringByAppendingPathComponent:backupName];
    
    // Save metadata
    NSDictionary *metadata = @{
        @"originalPath": savePath,
        @"gameName": gameName,
        @"slot": @(slot),
        @"backupDate": [NSDate date],
        @"backupPath": backupPath
    };
    
    NSString *metadataPath = [backupPath stringByAppendingString:@".meta"];
    [metadata writeToFile:metadataPath atomically:YES];
    
    return [fm copyItemAtPath:savePath toPath:backupPath error:nil];
}

- (BOOL)restoreGameSave:(NSString *)savePath slot:(int)slot {
    NSString *backupDir = [NSString stringWithFormat:@"%@/game_saves", kBackupPath];
    NSString *gameName = [self guessGameNameFromPath:savePath];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *backups = [fm contentsOfDirectoryAtPath:backupDir error:nil];
    
    for (NSString *backup in backups) {
        if ([backup containsString:gameName] && [backup containsString:[NSString stringWithFormat:@"slot%d", slot]]) {
            NSString *backupPath = [backupDir stringByAppendingPathComponent:backup];
            NSString *metadataPath = [backupPath stringByAppendingString:@".meta"];
            
            if ([fm fileExistsAtPath:metadataPath]) {
                NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
                if (metadata) {
                    // Backup current save first
                    [self backupGameSave:savePath slot:0];
                    
                    // Restore from backup
                    return [fm copyItemAtPath:backupPath toPath:savePath error:nil];
                }
            }
        }
    }
    
    return NO;
}

- (NSArray *)getSaveSlotsForGame:(NSString *)gameName {
    NSString *backupDir = [NSString stringWithFormat:@"%@/game_saves", kBackupPath];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *backups = [fm contentsOfDirectoryAtPath:backupDir error:nil];
    
    NSMutableArray *slots = [NSMutableArray array];
    
    for (NSString *backup in backups) {
        if ([backup containsString:gameName]) {
            NSString *backupPath = [backupDir stringByAppendingPathComponent:backup];
            NSString *metadataPath = [backupPath stringByAppendingString:@".meta"];
            
            if ([fm fileExistsAtPath:metadataPath]) {
                NSDictionary *metadata = [NSDictionary dictionaryWithContentsOfFile:metadataPath];
                if (metadata) {
                    [slots addObject:metadata];
                }
            }
        }
    }
    
    return [slots copy];
}

- (BOOL)validateSaveFile:(NSString *)savePath {
    NSFileManager *fm = [NSFileManager defaultManager];
    
    // Check if file exists
    if (![fm fileExistsAtPath:savePath]) {
        return NO;
    }
    
    // Check file size
    NSDictionary *attrs = [fm attributesOfItemAtPath:savePath error:nil];
    long long fileSize = [attrs[NSFileSize] longLongValue];
    
    if (fileSize <= 0 || fileSize > 100 * 1024 * 1024) { // 100MB limit
        return NO;
    }
    
    // Check if it's a valid file (not empty)
    NSData *data = [NSData dataWithContentsOfFile:savePath];
    if (data.length == 0) {
        return NO;
    }
    
    // Simple signature check for common save formats
    const char *bytes = (const char *)data.bytes;
    
    // Check for common save file headers
    if (data.length >= 4) {
        // Check for "SAV" magic
        if (strncmp(bytes, "SAV", 3) == 0) {
            return YES;
        }
        
        // Check for common game save patterns
        // (This is a simplified check - real validation would be game-specific)
    }
    
    return YES; // Assume valid if basic checks pass
}
@end

// MARK: - Main View Controller

@implementation ISMainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.title = @"iSaveTool";
    self.view.backgroundColor = [ISTheme primaryBackground];
    self.showApps = YES;
    self.favorites = [NSMutableArray array];
    
    [self loadFavorites];
    [self setupNavigationBar];
    [self setupBlurOverlay];
    [self setupUI];
    [self loadApps];
}

- (void)loadFavorites {
    if ([[NSFileManager defaultManager] fileExistsAtPath:kFavoritesPath]) {
        NSArray *favorites = [NSArray arrayWithContentsOfFile:kFavoritesPath];
        if (favorites) {
            self.favorites = [favorites mutableCopy];
        }
    }
}

- (void)saveFavorites {
    [self.favorites writeToFile:kFavoritesPath atomically:YES];
}

- (void)setupNavigationBar {
    UISegmentedControl *segmentControl = [[UISegmentedControl alloc] initWithItems:@[@"Apps", @"Files", @"Favorites", @"Tools"]];
    segmentControl.selectedSegmentIndex = 0;
    segmentControl.tintColor = [ISTheme accentColor];
    [segmentControl addTarget:self action:@selector(segmentChanged:) forControlEvents:UIControlEventValueChanged];
    
    self.navigationItem.titleView = segmentControl;
    
    UIImage *menuImage;
    UIImage *settingsImage;
    
    if (@available(iOS 13.0, *)) {
        menuImage = [UIImage systemImageNamed:@"ellipsis.circle"];
        settingsImage = [UIImage systemImageNamed:@"gear"];
    } else {
        menuImage = [UIImage imageNamed:@"menu"];
        settingsImage = [UIImage imageNamed:@"settings"];
    }
    
    UIBarButtonItem *menuButton = [[UIBarButtonItem alloc] initWithImage:menuImage
                                                                   style:UIBarButtonItemStylePlain
                                                                  target:self
                                                                  action:@selector(showMenu)];
    
    UIBarButtonItem *importButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAdd
                                                                                  target:self
                                                                                  action:@selector(importFile)];
    
    self.navigationItem.rightBarButtonItems = @[menuButton, importButton];
    
    UIBarButtonItem *settingsButton = [[UIBarButtonItem alloc] initWithImage:settingsImage
                                                                       style:UIBarButtonItemStylePlain
                                                                      target:self
                                                                      action:@selector(showSettings)];
    self.navigationItem.leftBarButtonItem = settingsButton;
    
    if (@available(iOS 13.0, *)) {
        UINavigationBarAppearance *appearance = [[UINavigationBarAppearance alloc] init];
        [appearance configureWithOpaqueBackground];
        appearance.backgroundColor = [ISTheme primaryBackground];
        appearance.titleTextAttributes = @{
            NSForegroundColorAttributeName: [ISTheme textPrimary],
            NSFontAttributeName: [UIFont boldSystemFontOfSize:18]
        };
        
        self.navigationController.navigationBar.standardAppearance = appearance;
        self.navigationController.navigationBar.scrollEdgeAppearance = appearance;
    } else {
        self.navigationController.navigationBar.barTintColor = [ISTheme primaryBackground];
        self.navigationController.navigationBar.titleTextAttributes = @{
            NSForegroundColorAttributeName: [ISTheme textPrimary]
        };
    }
}

- (void)segmentChanged:(UISegmentedControl *)sender {
    switch (sender.selectedSegmentIndex) {
        case 0:
            self.showApps = YES;
            [self loadApps];
            break;
        case 1:
            self.showApps = NO;
            [self loadFiles];
            break;
        case 2:
            [self showFavorites];
            break;
        case 3:
            [self showTools];
            break;
    }
}

- (void)setupBlurOverlay {
    UIBlurEffect *blurEffect;
    if (@available(iOS 13.0, *)) {
        blurEffect = [UIBlurEffect effectWithStyle:[ISTheme isDarkTheme] ? 
                     UIBlurEffectStyleSystemUltraThinMaterialDark : 
                     UIBlurEffectStyleSystemUltraThinMaterialLight];
    } else {
        blurEffect = [UIBlurEffect effectWithStyle:[ISTheme isDarkTheme] ? 
                     UIBlurEffectStyleDark : 
                     UIBlurEffectStyleLight];
    }
    
    UIVisualEffectView *blurView = [[UIVisualEffectView alloc] initWithEffect:blurEffect];
    blurView.frame = self.view.bounds;
    blurView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    blurView.alpha = 0.85;
    [self.view addSubview:blurView];
    self.blurOverlay = blurView;
}

- (void)setupUI {
    self.searchBar = [[UISearchBar alloc] initWithFrame:CGRectMake(0, 0, self.view.frame.size.width, 56)];
    self.searchBar.delegate = self;
    self.searchBar.placeholder = @"Search...";
    self.searchBar.barTintColor = [ISTheme primaryBackground];
    self.searchBar.searchBarStyle = UISearchBarStyleMinimal;
    self.searchBar.tintColor = [ISTheme accentColor];
    
    UITextField *searchField = [self.searchBar valueForKey:@"searchField"];
    if (searchField) {
        searchField.textColor = [ISTheme textPrimary];
        searchField.backgroundColor = [ISTheme secondaryBackground];
    }
    
    self.tableView = [[UITableView alloc] initWithFrame:self.view.bounds style:UITableViewStylePlain];
    self.tableView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.tableView.delegate = self;
    self.tableView.dataSource = self;
    self.tableView.backgroundColor = [UIColor clearColor];
    self.tableView.separatorColor = [[ISTheme textSecondary] colorWithAlphaComponent:0.3];
    self.tableView.tableHeaderView = self.searchBar;
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeInteractive;
    [self.tableView registerClass:[UITableViewCell class] forCellReuseIdentifier:@"Cell"];
    [self.view addSubview:self.tableView];
    
    self.refreshControl = [[UIRefreshControl alloc] init];
    self.refreshControl.tintColor = [ISTheme accentColor];
    [self.refreshControl addTarget:self action:@selector(refreshData) forControlEvents:UIControlEventValueChanged];
    if (@available(iOS 10.0, *)) {
        self.tableView.refreshControl = self.refreshControl;
    } else {
        [self.tableView addSubview:self.refreshControl];
    }
    
    if (@available(iOS 13.0, *)) {
        self.loadingIndicator = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleLarge];
    } else {
        self.loadingIndicator = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleWhiteLarge];
    }
    self.loadingIndicator.color = [ISTheme accentColor];
    self.loadingIndicator.center = self.view.center;
    self.loadingIndicator.hidesWhenStopped = YES;
    [self.view addSubview:self.loadingIndicator];
    
    self.emptyLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, self.view.center.y - 50, self.view.frame.size.width - 40, 100)];
    self.emptyLabel.text = @"No data found";
    self.emptyLabel.textColor = [ISTheme textSecondary];
    self.emptyLabel.textAlignment = NSTextAlignmentCenter;
    self.emptyLabel.numberOfLines = 0;
    self.emptyLabel.font = [UIFont systemFontOfSize:16];
    self.emptyLabel.hidden = YES;
    [self.view addSubview:self.emptyLabel];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    
    [[ISAudioManager shared] playBackgroundMusic];
    [self animateInitialAppearance];
}

- (void)animateInitialAppearance {
    self.tableView.alpha = 0;
    self.searchBar.alpha = 0;
    
    [UIView animateWithDuration:0.3 delay:0.1 options:UIViewAnimationOptionCurveEaseOut animations:^{
        self.searchBar.alpha = 1;
    } completion:nil];
    
    [UIView animateWithDuration:0.5 delay:0.2 options:UIViewAnimationOptionCurveEaseOut animations:^{
        self.tableView.alpha = 1;
    } completion:nil];
}

- (void)loadApps {
    [self.loadingIndicator startAnimating];
    self.searchBar.placeholder = @"Search apps...";
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray *apps = [[ISFileManager shared] getInstalledApps];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            self.apps = apps;
            self.filteredApps = apps;
            [self.tableView reloadData];
            [self.loadingIndicator stopAnimating];
            [self.refreshControl endRefreshing];
            
            self.emptyLabel.hidden = (apps.count > 0);
            self.emptyLabel.text = @"No apps with plist files found";
            
            if (apps.count > 0 && SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"10.0")) {
                UISelectionFeedbackGenerator *generator = [[UISelectionFeedbackGenerator alloc] init];
                [generator selectionChanged];
            }
        });
    });
}

- (void)loadFiles {
    [self.loadingIndicator startAnimating];
    self.searchBar.placeholder = @"Search save files...";
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray *files = [[ISFileManager shared] getSaveFilesAtPath:kDefaultSavePath];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            self.apps = files;
            self.filteredApps = files;
            [self.tableView reloadData];
            [self.loadingIndicator stopAnimating];
            [self.refreshControl endRefreshing];
            
            self.emptyLabel.hidden = (files.count > 0);
            self.emptyLabel.text = @"No save files found\nCheck if /mnt/data/save exists";
        });
    });
}

- (void)showFavorites {
    if (self.favorites.count == 0) {
        self.filteredApps = @[];
        [self.tableView reloadData];
        self.emptyLabel.hidden = NO;
        self.emptyLabel.text = @"No favorites added yet\nLong press any item to add to favorites";
        return;
    }
    
    NSMutableArray *favoriteItems = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    
    for (NSString *path in self.favorites) {
        if ([fm fileExistsAtPath:path]) {
            NSDictionary *attrs = [fm attributesOfItemAtPath:path error:nil];
            NSMutableDictionary *item = [NSMutableDictionary dictionary];
            item[@"name"] = [path lastPathComponent];
            item[@"path"] = path;
            item[@"size"] = attrs[NSFileSize] ?: @0;
            item[@"modified"] = attrs[NSFileModificationDate] ?: [NSDate date];
            item[@"isFavorite"] = @YES;
            
            [favoriteItems addObject:item];
        }
    }
    
    self.filteredApps = favoriteItems;
    [self.tableView reloadData];
    self.emptyLabel.hidden = (favoriteItems.count > 0);
}

- (void)showTools {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Tools"
                                                                   message:@"Select a tool:"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Hex Editor"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self openHexEditor];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Plist Editor"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self openPlistEditor];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"SQLite Browser"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self openSQLiteBrowser];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"File Compare"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self compareFiles];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Encrypt/Decrypt"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self encryptDecryptTool];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"WebDAV Server"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self webDAVServer];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Game Save Manager"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self gameSaveManager];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)refreshData {
    UISegmentedControl *segmentControl = (UISegmentedControl *)self.navigationItem.titleView;
    
    switch (segmentControl.selectedSegmentIndex) {
        case 0:
            [self loadApps];
            break;
        case 1:
            [self loadFiles];
            break;
        case 2:
            [self showFavorites];
            break;
    }
}

- (void)showMenu {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:nil
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Batch Backup"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self batchBackup];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Export All"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self exportAllFiles];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Change Directory"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self changeDirectory];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"View Backups"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self showBackups];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Scan Game Saves"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self scanGameSaves];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Storage Analyzer"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self storageAnalyzer];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        alert.popoverPresentationController.barButtonItem = self.navigationItem.rightBarButtonItems.firstObject;
    }
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)importFile {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Import Options"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"From Files App"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self importFromFiles];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"WebDAV Transfer"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self webDAVTransfer];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"QR Code"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self qrCodeImport];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showSettings {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Settings"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    BOOL isMusicPlaying = [[ISAudioManager shared] isMusicPlaying];
    NSString *musicTitle = isMusicPlaying ? @"Turn Off Background Music" : @"Turn On Background Music";
    
    [alert addAction:[UIAlertAction actionWithTitle:musicTitle
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [[ISAudioManager shared] toggleMusic];
        NSString *status = [[ISAudioManager shared] isMusicPlaying] ? @"ON" : @"OFF";
        [self showAlertWithTitle:@"Music" message:[NSString stringWithFormat:@"Background music is now %@", status]];
    }]];
    
    NSString *themeTitle = [ISTheme isDarkTheme] ? @"Switch to Light Theme" : @"Switch to Dark Theme";
    [alert addAction:[UIAlertAction actionWithTitle:themeTitle
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [ISTheme setDarkTheme:![ISTheme isDarkTheme]];
        [self updateTheme];
        [self showAlertWithTitle:@"Theme" message:[NSString stringWithFormat:@"Theme changed to %@", 
                                                   [ISTheme isDarkTheme] ? @"Dark" : @"Light"]];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Change Accent Color"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self changeAccentColor];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Security Settings"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self securitySettings];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Clear Logs"
                                              style:UIAlertActionStyleDestructive
                                            handler:^(UIAlertAction *action) {
        [self clearLogs];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"About"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self showAbout];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)updateTheme {
    self.view.backgroundColor = [ISTheme primaryBackground];
    self.tableView.backgroundColor = [UIColor clearColor];
    self.tableView.separatorColor = [[ISTheme textSecondary] colorWithAlphaComponent:0.3];
    self.searchBar.barTintColor = [ISTheme primaryBackground];
    
    UITextField *searchField = [self.searchBar valueForKey:@"searchField"];
    if (searchField) {
        searchField.textColor = [ISTheme textPrimary];
        searchField.backgroundColor = [ISTheme secondaryBackground];
    }
    
    [self.tableView reloadData];
    
    [self.blurOverlay removeFromSuperview];
    [self setupBlurOverlay];
    [self.view bringSubviewToFront:self.tableView];
    [self.view bringSubviewToFront:self.loadingIndicator];
    [self.view bringSubviewToFront:self.emptyLabel];
}

- (void)changeAccentColor {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Accent Color"
                                                                   message:@"Enter hex color (e.g., #FF0000):"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"#FF0000";
        textField.keyboardType = UIKeyboardTypeASCIICapable;
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Apply"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *colorHex = alert.textFields.firstObject.text;
        [ISTheme setCustomAccentColor:colorHex];
        [self updateTheme];
        [self showAlertWithTitle:@"Success" message:@"Accent color changed"];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Reset to Default"
                                              style:UIAlertActionStyleDestructive
                                            handler:^(UIAlertAction *action) {
        [ISTheme setCustomAccentColor:nil];
        [self updateTheme];
        [self showAlertWithTitle:@"Success" message:@"Accent color reset to default"];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)securitySettings {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Security"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Set Master Password"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self setMasterPassword];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Encrypt Backups"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self encryptBackups];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"App Lock"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self appLock];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)setMasterPassword {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Master Password"
                                                                   message:@"Set a master password for encryption:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Enter password";
        textField.secureTextEntry = YES;
    }];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Confirm password";
        textField.secureTextEntry = YES;
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Set"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *password = alert.textFields[0].text;
        NSString *confirm = alert.textFields[1].text;
        
        if (![password isEqualToString:confirm]) {
            [self showAlertWithTitle:@"Error" message:@"Passwords don't match"];
            return;
        }
        
        if (![ISEncryptionManager validatePassword:password]) {
            [self showAlertWithTitle:@"Error" message:@"Password must be at least 6 characters with letters and numbers"];
            return;
        }
        
        // Save password hash
        NSString *hash = [ISEncryptionManager hashString:password algorithm:@"SHA256"];
        [[NSUserDefaults standardUserDefaults] setObject:hash forKey:@"MasterPasswordHash"];
        [[NSUserDefaults standardUserDefaults] synchronize];
        
        [self showAlertWithTitle:@"Success" message:@"Master password set"];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)encryptBackups {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Encrypt Backups"
                                                                   message:@"Encrypt all backups with password?"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Encrypt"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self showAlertWithTitle:@"Info" message:@"This feature will be implemented in next version"];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)appLock {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"App Lock"
                                                                   message:@"Require password to open app?"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Enable"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@"AppLockEnabled"];
        [[NSUserDefaults standardUserDefaults] synchronize];
        [self showAlertWithTitle:@"Success" message:@"App lock enabled"];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Disable"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [[NSUserDefaults standardUserDefaults] setBool:NO forKey:@"AppLockEnabled"];
        [[NSUserDefaults standardUserDefaults] synchronize];
        [self showAlertWithTitle:@"Success" message:@"App lock disabled"];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)batchBackup {
    if (self.showApps) {
        [self showAlertWithTitle:@"Info" message:@"Select an app to backup its plist files"];
        return;
    }
    
    if (self.filteredApps.count == 0) {
        [self showAlertWithTitle:@"No Files" message:@"No files to backup"];
        return;
    }
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Batch Backup"
                                                                   message:[NSString stringWithFormat:@"Backup %lu files?", (unsigned long)self.filteredApps.count]
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Backup"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self performBatchBackup];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Backup & Encrypt"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self performEncryptedBatchBackup];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)performBatchBackup {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int successCount = 0;
        
        for (NSDictionary *fileInfo in self.filteredApps) {
            NSString *path = fileInfo[@"path"];
            NSError *error = nil;
            if ([[ISFileManager shared] backupFile:path error:&error]) {
                successCount++;
            } else {
                [ISLogger logError:@"Batch backup failed for %@: %@", path, error.localizedDescription];
            }
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            [self showAlertWithTitle:@"Batch Backup Complete"
                             message:[NSString stringWithFormat:@"Successfully backed up %d of %lu files", successCount, (unsigned long)self.filteredApps.count]];
            
            if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"10.0")) {
                UINotificationFeedbackGenerator *generator = [[UINotificationFeedbackGenerator alloc] init];
                UINotificationFeedbackType type = (successCount > 0) ? UINotificationFeedbackTypeSuccess : UINotificationFeedbackTypeError;
                [generator notificationOccurred:type];
            }
        });
    });
}

- (void)performEncryptedBatchBackup {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Encryption Password"
                                                                   message:@"Enter password for encryption:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Password";
        textField.secureTextEntry = YES;
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Encrypt"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *password = alert.textFields.firstObject.text;
        [self performBatchBackupWithEncryption:password];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)performBatchBackupWithEncryption:(NSString *)password {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int successCount = 0;
        
        for (NSDictionary *fileInfo in self.filteredApps) {
            NSString *path = fileInfo[@"path"];
            NSError *error = nil;
            
            // Read file
            NSData *fileData = [[ISFileManager shared] readFileAtPath:path error:&error];
            if (!fileData) continue;
            
            // Encrypt
            NSData *encryptedData = [ISEncryptionManager encryptData:fileData password:password];
            if (!encryptedData) continue;
            
            // Save encrypted backup
            NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
            [formatter setDateFormat:@"yyyyMMdd-HHmmss"];
            NSString *timestamp = [formatter stringFromDate:[NSDate date]];
            NSString *fileName = [path.lastPathComponent stringByAppendingFormat:@".%@.enc.bak", timestamp];
            NSString *backupPath = [kEncryptedPath stringByAppendingPathComponent:fileName];
            
            if ([encryptedData writeToFile:backupPath options:NSDataWritingAtomic error:&error]) {
                successCount++;
            }
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            [self showAlertWithTitle:@"Encrypted Backup Complete"
                             message:[NSString stringWithFormat:@"Successfully encrypted and backed up %d of %lu files", successCount, (unsigned long)self.filteredApps.count]];
            
            if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"10.0")) {
                UINotificationFeedbackGenerator *generator = [[UINotificationFeedbackGenerator alloc] init];
                UINotificationFeedbackType type = (successCount > 0) ? UINotificationFeedbackTypeSuccess : UINotificationFeedbackTypeError;
                [generator notificationOccurred:type];
            }
        });
    });
}

- (void)exportAllFiles {
    [self showAlertWithTitle:@"Export" message:@"Select individual files to export"];
}

- (void)changeDirectory {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Change Directory"
                                                                   message:@"Enter new save directory path:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"/path/to/save/files";
        textField.text = kDefaultSavePath;
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Change"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *newPath = alert.textFields.firstObject.text;
        if (newPath.length > 0) {
            [ISLogger log:@"User changed directory to: %@", newPath];
            [self showAlertWithTitle:@"Info" message:@"Please restart app for path change to take effect"];
        }
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showBackups {
    NSArray *backups = [[ISFileManager shared] getBackupsForFile:@""];
    
    if (backups.count == 0) {
        [self showAlertWithTitle:@"No Backups" message:@"No backup files found"];
        return;
    }
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Backups"
                                                                   message:[NSString stringWithFormat:@"Found %lu backup files", (unsigned long)backups.count]
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    for (NSDictionary *backup in backups) {
        NSString *name = backup[@"name"];
        NSString *size = [NSByteCountFormatter stringFromByteCount:[backup[@"size"] longLongValue]
                                                         countStyle:NSByteCountFormatterCountStyleFile];
        
        [alert addAction:[UIAlertAction actionWithTitle:[NSString stringWithFormat:@"%@ (%@)", name, size]
                                                  style:UIAlertActionStyleDefault
                                                handler:nil]];
    }
    
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)scanGameSaves {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray *gameSaves = [[ISGameSaveManager shared] scanForGameSaves];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            if (gameSaves.count == 0) {
                [self showAlertWithTitle:@"No Game Saves" message:@"No game save files found"];
                return;
            }
            
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Game Saves Found"
                                                                           message:[NSString stringWithFormat:@"Found %lu game save files", (unsigned long)gameSaves.count]
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            
            for (NSDictionary *save in gameSaves) {
                NSString *name = save[@"gameName"];
                NSString *size = [NSByteCountFormatter stringFromByteCount:[save[@"size"] longLongValue]
                                                                 countStyle:NSByteCountFormatterCountStyleFile];
                
                [alert addAction:[UIAlertAction actionWithTitle:[NSString stringWithFormat:@"%@ (%@)", name, size]
                                                          style:UIAlertActionStyleDefault
                                                        handler:^(UIAlertAction *action) {
                    [self showGameSaveOptions:save];
                }]];
            }
            
            [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                                      style:UIAlertActionStyleCancel
                                                    handler:nil]];
            
            [self presentViewController:alert animated:YES completion:nil];
        });
    });
}

- (void)storageAnalyzer {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray *apps = [[ISFileManager shared] getInstalledApps];
        NSMutableArray *storageInfo = [NSMutableArray array];
        
        for (ISAppInfo *app in apps) {
            NSMutableDictionary *info = [NSMutableDictionary dictionary];
            info[@"name"] = app.appName;
            info[@"size"] = @(app.totalSize);
            info[@"plistCount"] = @(app.plistFiles.count);
            info[@"saveCount"] = @(app.saveFiles.count);
            [storageInfo addObject:info];
        }
        
        // Sort by size
        [storageInfo sortUsingComparator:^NSComparisonResult(NSDictionary *obj1, NSDictionary *obj2) {
            long long size1 = [obj1[@"size"] longLongValue];
            long long size2 = [obj2[@"size"] longLongValue];
            return size1 < size2 ? NSOrderedDescending : NSOrderedAscending;
        }];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            NSMutableString *report = [NSMutableString stringWithString:@"Storage Usage Report:\n\n"];
            long long totalSize = 0;
            
            for (NSDictionary *info in storageInfo) {
                NSString *sizeStr = [NSByteCountFormatter stringFromByteCount:[info[@"size"] longLongValue]
                                                                    countStyle:NSByteCountFormatterCountStyleFile];
                [report appendFormat:@"%@: %@ (%@ plist, %@ saves)\n",
                 info[@"name"], sizeStr, info[@"plistCount"], info[@"saveCount"]];
                totalSize += [info[@"size"] longLongValue];
            }
            
            [report appendFormat:@"\nTotal: %@\n", 
             [NSByteCountFormatter stringFromByteCount:totalSize countStyle:NSByteCountFormatterCountStyleFile]];
            
            [self showAlertWithTitle:@"Storage Analyzer" message:report];
        });
    });
}

- (void)clearLogs {
    NSString *logFile = [NSString stringWithFormat:@"%@/isavetool.log", kLogPath];
    NSError *error = nil;
    
    if ([[NSFileManager defaultManager] removeItemAtPath:logFile error:&error]) {
        [ISLogger log:@"Logs cleared by user"];
        [self showAlertWithTitle:@"Success" message:@"Logs cleared"];
    } else {
        [self showAlertWithTitle:@"Error" message:error.localizedDescription ?: @"Failed to clear logs"];
    }
}

- (void)showAbout {
    NSString *message = @"iSaveTool v1.118\n\n"
                       @"Jailbroken iOS devices save/plist management tool\n\n"
                       @"Features:\n"
                       @"• Plist Editor (XML/JSON/Tree)\n"
                       @"• Hex Editor/Binary Viewer\n"
                       @"• SQLite Database Browser\n"
                       @"• Game Save Manager\n"
                       @"• AES-256 Encryption\n"
                       @"• WebDAV Server\n"
                       @"• Batch Operations\n"
                       @"• Storage Analyzer\n"
                       @"• Light/Dark Theme\n"
                       @"• Custom Accent Colors\n\n"
                       @"© 2025 iSaveTool - By iosmen";
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"About iSaveTool v1.118"
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)openHexEditor {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Open File"
                                                                   message:@"Enter file path for hex editor:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"/path/to/file";
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Open"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *filePath = alert.textFields.firstObject.text;
        [self openFileInHexEditor:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)openPlistEditor {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Open Plist"
                                                                   message:@"Enter plist file path:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"/path/to/plist";
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Open"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *filePath = alert.textFields.firstObject.text;
        [self openFileInPlistEditor:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)openSQLiteBrowser {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Open Database"
                                                                   message:@"Enter SQLite database path:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"/path/to/database.sqlite";
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Open"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *dbPath = alert.textFields.firstObject.text;
        [self openDatabaseInBrowser:dbPath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)compareFiles {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Compare Files"
                                                                   message:@"Enter two file paths to compare:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"First file path";
    }];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Second file path";
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Compare"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *file1 = alert.textFields[0].text;
        NSString *file2 = alert.textFields[1].text;
        [self compareTwoFiles:file1 and:file2];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)encryptDecryptTool {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Encrypt/Decrypt"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Encrypt File"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self encryptFileTool];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Decrypt File"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self decryptFileTool];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Generate Hash"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self generateHashTool];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)webDAVServer {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"WebDAV Server"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    if ([[ISWebDAVServer shared] isRunning]) {
        [alert addAction:[UIAlertAction actionWithTitle:@"Stop Server"
                                                  style:UIAlertActionStyleDestructive
                                                handler:^(UIAlertAction *action) {
            [[ISWebDAVServer shared] stopServer];
            [self showAlertWithTitle:@"Server Stopped" message:@"WebDAV server has been stopped"];
        }]];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Server Info"
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            NSString *url = [[ISWebDAVServer shared] serverURL];
            [self showAlertWithTitle:@"Server Running" 
                             message:[NSString stringWithFormat:@"Server is running at:\n%@\n\nUse WebDAV client to connect.", url]];
        }]];
    } else {
        [alert addAction:[UIAlertAction actionWithTitle:@"Start Server (Port 8080)"
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            if ([[ISWebDAVServer shared] startServerOnPort:8080]) {
                NSString *url = [[ISWebDAVServer shared] serverURL];
                [self showAlertWithTitle:@"Server Started" 
                                 message:[NSString stringWithFormat:@"Server started at:\n%@\n\nUse WebDAV client to connect.", url]];
            } else {
                [self showAlertWithTitle:@"Error" message:@"Failed to start server"];
            }
        }]];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Custom Port"
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            [self startCustomPortServer];
        }]];
    }
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)gameSaveManager {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Game Save Manager"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Scan for Game Saves"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self scanGameSaves];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Manage Save Slots"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self manageSaveSlots];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Validate Save File"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self validateSaveFile];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.filteredApps.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"Cell" forIndexPath:indexPath];
    cell.backgroundColor = [UIColor clearColor];
    
    [cell.contentView.subviews makeObjectsPerformSelector:@selector(removeFromSuperview)];
    
    UISegmentedControl *segmentControl = (UISegmentedControl *)self.navigationItem.titleView;
    
    if (segmentControl.selectedSegmentIndex == 0) {
        // Apps view
        ISAppInfo *appInfo = self.filteredApps[indexPath.row];
        
        UIView *cardView = [[UIView alloc] initWithFrame:CGRectMake(10, 5, cell.contentView.frame.size.width - 20, 90)];
        cardView.backgroundColor = [ISTheme tableViewCellBackground];
        cardView.layer.cornerRadius = 12;
        cardView.layer.shadowColor = [UIColor blackColor].CGColor;
        cardView.layer.shadowOffset = CGSizeMake(0, 2);
        cardView.layer.shadowOpacity = 0.2;
        cardView.layer.shadowRadius = 4;
        cardView.autoresizingMask = UIViewAutoresizingFlexibleWidth;
        
        UIImageView *iconView = [[UIImageView alloc] initWithFrame:CGRectMake(15, 25, 40, 40)];
        
        UIImage *iconImage;
        if (@available(iOS 13.0, *)) {
            iconImage = [UIImage systemImageNamed:@"app.fill"];
        } else {
            iconImage = [UIImage imageNamed:@"app_fill"];
        }
        
        iconView.image = iconImage;
        iconView.tintColor = [ISTheme accentColor];
        [cardView addSubview:iconView];
        
        UILabel *nameLabel = [[UILabel alloc] initWithFrame:CGRectMake(65, 15, cardView.frame.size.width - 80, 24)];
        nameLabel.text = appInfo.appName;
        nameLabel.textColor = [ISTheme textPrimary];
        nameLabel.font = [UIFont boldSystemFontOfSize:16];
        nameLabel.lineBreakMode = NSLineBreakByTruncatingMiddle;
        [cardView addSubview:nameLabel];
        
        UILabel *detailsLabel = [[UILabel alloc] initWithFrame:CGRectMake(65, 40, cardView.frame.size.width - 80, 18)];
        detailsLabel.text = [NSString stringWithFormat:@"%@ • %lu plist, %lu saves", 
                           appInfo.bundleId, 
                           (unsigned long)appInfo.plistFiles.count,
                           (unsigned long)appInfo.saveFiles.count];
        detailsLabel.textColor = [ISTheme textSecondary];
        detailsLabel.font = [UIFont systemFontOfSize:12];
        [cardView addSubview:detailsLabel];
        
        UILabel *sizeLabel = [[UILabel alloc] initWithFrame:CGRectMake(65, 58, cardView.frame.size.width - 80, 18)];
        sizeLabel.text = [NSByteCountFormatter stringFromByteCount:appInfo.totalSize
                                                         countStyle:NSByteCountFormatterCountStyleFile];
        sizeLabel.textColor = [ISTheme highlightColor];
        sizeLabel.font = [UIFont systemFontOfSize:12];
        [cardView addSubview:sizeLabel];
        
        // Favorite button
        UIButton *favoriteButton = [UIButton buttonWithType:UIButtonTypeSystem];
        favoriteButton.frame = CGRectMake(cardView.frame.size.width - 50, 25, 40, 40);
        [favoriteButton setImage:[UIImage systemImageNamed:@"star"] forState:UIControlStateNormal];
        [favoriteButton setTintColor:[ISTheme highlightColor]];
        [favoriteButton addTarget:self action:@selector(favoriteButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
        favoriteButton.tag = indexPath.row;
        [cardView addSubview:favoriteButton];
        
        [cell.contentView addSubview:cardView];
        
    } else if (segmentControl.selectedSegmentIndex == 1 || segmentControl.selectedSegmentIndex == 2) {
        // Files or Favorites view
        NSDictionary *fileInfo = self.filteredApps[indexPath.row];
        
        UIView *cardView = [[UIView alloc] initWithFrame:CGRectMake(10, 5, cell.contentView.frame.size.width - 20, 70)];
        cardView.backgroundColor = [ISTheme tableViewCellBackground];
        cardView.layer.cornerRadius = 12;
        cardView.layer.shadowColor = [UIColor blackColor].CGColor;
        cardView.layer.shadowOffset = CGSizeMake(0, 2);
        cardView.layer.shadowOpacity = 0.2;
        cardView.layer.shadowRadius = 4;
        cardView.autoresizingMask = UIViewAutoresizingFlexibleWidth;
        
        UIImageView *iconView = [[UIImageView alloc] initWithFrame:CGRectMake(15, 15, 40, 40)];
        BOOL isBinary = [fileInfo[@"isBinary"] boolValue];
        BOOL isFavorite = [fileInfo[@"isFavorite"] boolValue];
        
        UIImage *iconImage;
        if (@available(iOS 13.0, *)) {
            if (isFavorite) {
                iconImage = [UIImage systemImageNamed:@"star.fill"];
            } else {
                iconImage = [UIImage systemImageNamed:isBinary ? @"doc.fill" : @"doc.text.fill"];
            }
        } else {
            if (isFavorite) {
                iconImage = [UIImage imageNamed:@"star_fill"];
            } else {
                iconImage = [UIImage imageNamed:isBinary ? @"doc_fill" : @"doc_text_fill"];
            }
        }
        
        iconView.image = iconImage;
        iconView.tintColor = isFavorite ? [ISTheme highlightColor] : (isBinary ? [ISTheme accentColor] : [ISTheme infoColor]);
        [cardView addSubview:iconView];
        
        UILabel *nameLabel = [[UILabel alloc] initWithFrame:CGRectMake(65, 12, cardView.frame.size.width - 80, 24)];
        nameLabel.text = fileInfo[@"name"];
        nameLabel.textColor = [ISTheme textPrimary];
        nameLabel.font = [UIFont boldSystemFontOfSize:16];
        nameLabel.lineBreakMode = NSLineBreakByTruncatingMiddle;
        [cardView addSubview:nameLabel];
        
        UILabel *detailsLabel = [[UILabel alloc] initWithFrame:CGRectMake(65, 36, cardView.frame.size.width - 80, 18)];
        
        NSDate *modified = fileInfo[@"modified"];
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        [formatter setDateFormat:@"MMM dd, HH:mm"];
        
        NSString *sizeStr = [NSByteCountFormatter stringFromByteCount:[fileInfo[@"size"] longLongValue]
                                                            countStyle:NSByteCountFormatterCountStyleFile];
        
        detailsLabel.text = [NSString stringWithFormat:@"%@ • %@", sizeStr, [formatter stringFromDate:modified]];
        detailsLabel.textColor = [ISTheme textSecondary];
        detailsLabel.font = [UIFont systemFontOfSize:12];
        [cardView addSubview:detailsLabel];
        
        if (isBinary && !isFavorite) {
            UILabel *binaryBadge = [[UILabel alloc] initWithFrame:CGRectMake(cardView.frame.size.width - 60, 15, 50, 20)];
            binaryBadge.text = @"BIN";
            binaryBadge.textColor = [ISTheme accentColor];
            binaryBadge.font = [UIFont boldSystemFontOfSize:10];
            binaryBadge.textAlignment = NSTextAlignmentCenter;
            binaryBadge.layer.borderColor = [ISTheme accentColor].CGColor;
            binaryBadge.layer.borderWidth = 1;
            binaryBadge.layer.cornerRadius = 4;
            [cardView addSubview:binaryBadge];
        }
        
        [cell.contentView addSubview:cardView];
    }
    
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    UISegmentedControl *segmentControl = (UISegmentedControl *)self.navigationItem.titleView;
    
    if (segmentControl.selectedSegmentIndex == 0) {
        return 100;
    } else {
        return 80;
    }
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    
    UISegmentedControl *segmentControl = (UISegmentedControl *)self.navigationItem.titleView;
    
    if (segmentControl.selectedSegmentIndex == 0) {
        ISAppInfo *appInfo = self.filteredApps[indexPath.row];
        [self showAppOptions:appInfo];
    } else if (segmentControl.selectedSegmentIndex == 1 || segmentControl.selectedSegmentIndex == 2) {
        NSDictionary *fileInfo = self.filteredApps[indexPath.row];
        [self showFileOptions:fileInfo];
    }
}

- (UISwipeActionsConfiguration *)tableView:(UITableView *)tableView trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)indexPath {
    UISegmentedControl *segmentControl = (UISegmentedControl *)self.navigationItem.titleView;
    
    if (segmentControl.selectedSegmentIndex == 2) {
        // Favorites view - only remove action
        UIContextualAction *removeAction = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleDestructive
                                                                                   title:@"Remove"
                                                                                 handler:^(UIContextualAction * _Nonnull action, __kindof UIView * _Nonnull sourceView, void (^ _Nonnull completionHandler)(BOOL)) {
            NSDictionary *fileInfo = self.filteredApps[indexPath.row];
            NSString *path = fileInfo[@"path"];
            
            [self.favorites removeObject:path];
            [self saveFavorites];
            [self showFavorites];
            
            completionHandler(YES);
        }];
        
        removeAction.backgroundColor = [ISTheme errorColor];
        
        return [UISwipeActionsConfiguration configurationWithActions:@[removeAction]];
    } else {
        // Apps/Files view - favorite and backup actions
        UIContextualAction *favoriteAction = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
                                                                                     title:@"Favorite"
                                                                                   handler:^(UIContextualAction * _Nonnull action, __kindof UIView * _Nonnull sourceView, void (^ _Nonnull completionHandler)(BOOL)) {
            NSString *path = nil;
            
            if (segmentControl.selectedSegmentIndex == 0) {
                ISAppInfo *appInfo = self.filteredApps[indexPath.row];
                path = appInfo.dataPath;
            } else {
                NSDictionary *fileInfo = self.filteredApps[indexPath.row];
                path = fileInfo[@"path"];
            }
            
            if (![self.favorites containsObject:path]) {
                [self.favorites addObject:path];
                [self saveFavorites];
                [self showAlertWithTitle:@"Added to Favorites" message:@"Item added to favorites"];
            }
            
            completionHandler(YES);
        }];
        
        UIContextualAction *backupAction = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
                                                                                   title:@"Backup"
                                                                                 handler:^(UIContextualAction * _Nonnull action, __kindof UIView * _Nonnull sourceView, void (^ _Nonnull completionHandler)(BOOL)) {
            NSString *path = nil;
            
            if (segmentControl.selectedSegmentIndex == 0) {
                ISAppInfo *appInfo = self.filteredApps[indexPath.row];
                path = appInfo.dataPath;
            } else {
                NSDictionary *fileInfo = self.filteredApps[indexPath.row];
                path = fileInfo[@"path"];
            }
            
            NSError *error = nil;
            if ([[ISFileManager shared] backupFile:path error:&error]) {
                [self showAlertWithTitle:@"Backup Created" message:@"File backed up successfully"];
            } else {
                [self showAlertWithTitle:@"Backup Failed" message:error.localizedDescription];
            }
            
            completionHandler(YES);
        }];
        
        favoriteAction.backgroundColor = [ISTheme highlightColor];
        backupAction.backgroundColor = [ISTheme accentColor];
        
        return [UISwipeActionsConfiguration configurationWithActions:@[favoriteAction, backupAction]];
    }
}

- (void)showAppOptions:(ISAppInfo *)appInfo {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:appInfo.appName
                                                                   message:@"Select action:"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    if (appInfo.plistFiles.count > 0) {
        [alert addAction:[UIAlertAction actionWithTitle:@"View Plist Files"
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            [self showAppPlistFiles:appInfo];
        }]];
    }
    
    if (appInfo.saveFiles.count > 0) {
        [alert addAction:[UIAlertAction actionWithTitle:@"View Save Files"
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            [self showAppSaveFiles:appInfo];
        }]];
    }
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Backup App Data"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self backupAppData:appInfo];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Storage Info"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self showAppStorageInfo:appInfo];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        UITableViewCell *cell = [self.tableView cellForRowAtIndexPath:[NSIndexPath indexPathForRow:[self.filteredApps indexOfObject:appInfo] inSection:0]];
        alert.popoverPresentationController.sourceView = cell;
        alert.popoverPresentationController.sourceRect = cell.bounds;
    }
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showAppPlistFiles:(ISAppInfo *)appInfo {
    if (appInfo.plistFiles.count == 0) {
        [self showAlertWithTitle:@"No Plist Files" message:@"No plist files found in this app"];
        return;
    }
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:appInfo.appName
                                                                   message:[NSString stringWithFormat:@"Select a plist file (%lu found):", (unsigned long)appInfo.plistFiles.count]
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    for (NSDictionary *plistInfo in appInfo.plistFiles) {
        NSString *fileName = plistInfo[@"name"];
        NSString *relativePath = plistInfo[@"relativePath"];
        
        [alert addAction:[UIAlertAction actionWithTitle:[NSString stringWithFormat:@"%@", relativePath]
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            [self showPlistFileOptions:plistInfo appName:appInfo.appName];
        }]];
    }
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        UITableViewCell *cell = [self.tableView cellForRowAtIndexPath:[NSIndexPath indexPathForRow:[self.filteredApps indexOfObject:appInfo] inSection:0]];
        alert.popoverPresentationController.sourceView = cell;
        alert.popoverPresentationController.sourceRect = cell.bounds;
    }
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showAppSaveFiles:(ISAppInfo *)appInfo {
    if (appInfo.saveFiles.count == 0) {
        [self showAlertWithTitle:@"No Save Files" message:@"No save files found in this app"];
        return;
    }
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:appInfo.appName
                                                                   message:[NSString stringWithFormat:@"Select a save file (%lu found):", (unsigned long)appInfo.saveFiles.count]
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    for (NSDictionary *saveInfo in appInfo.saveFiles) {
        NSString *fileName = saveInfo[@"name"];
        NSString *relativePath = saveInfo[@"relativePath"];
        
        [alert addAction:[UIAlertAction actionWithTitle:[NSString stringWithFormat:@"%@", relativePath]
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            [self showSaveFileOptions:saveInfo appName:appInfo.appName];
        }]];
    }
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        UITableViewCell *cell = [self.tableView cellForRowAtIndexPath:[NSIndexPath indexPathForRow:[self.filteredApps indexOfObject:appInfo] inSection:0]];
        alert.popoverPresentationController.sourceView = cell;
        alert.popoverPresentationController.sourceRect = cell.bounds;
    }
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)backupAppData:(ISAppInfo *)appInfo {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int successCount = 0;
        int totalCount = (int)(appInfo.plistFiles.count + appInfo.saveFiles.count);
        
        // Backup plist files
        for (NSDictionary *plistInfo in appInfo.plistFiles) {
            NSString *path = plistInfo[@"path"];
            NSError *error = nil;
            if ([[ISFileManager shared] backupFile:path error:&error]) {
                successCount++;
            }
        }
        
        // Backup save files
        for (NSDictionary *saveInfo in appInfo.saveFiles) {
            NSString *path = saveInfo[@"path"];
            NSError *error = nil;
            if ([[ISFileManager shared] backupFile:path error:&error]) {
                successCount++;
            }
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            [self showAlertWithTitle:@"App Backup Complete"
                             message:[NSString stringWithFormat:@"Successfully backed up %d of %d files", successCount, totalCount]];
        });
    });
}

- (void)showAppStorageInfo:(ISAppInfo *)appInfo {
    NSString *sizeStr = [NSByteCountFormatter stringFromByteCount:appInfo.totalSize
                                                        countStyle:NSByteCountFormatterCountStyleFile];
    
    NSString *message = [NSString stringWithFormat:@"App: %@\n"
                        @"Bundle ID: %@\n"
                        @"Total Size: %@\n"
                        @"Plist Files: %lu\n"
                        @"Save Files: %lu\n"
                        @"Last Modified: %@",
                        appInfo.appName,
                        appInfo.bundleId,
                        sizeStr,
                        (unsigned long)appInfo.plistFiles.count,
                        (unsigned long)appInfo.saveFiles.count,
                        appInfo.lastModified];
    
    [self showAlertWithTitle:@"Storage Information" message:message];
}

- (void)showPlistFileOptions:(NSDictionary *)plistInfo appName:(NSString *)appName {
    NSString *filePath = plistInfo[@"path"];
    NSString *fileName = plistInfo[@"name"];
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:[NSString stringWithFormat:@"%@ - %@", appName, fileName]
                                                                   message:@"Select action:"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Open Plist Editor"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self openAdvancedPlistEditor:plistInfo];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Open Binary Viewer"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self openHexViewer:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Backup"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self backupFile:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Export"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self showExportOptions:plistInfo];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showSaveFileOptions:(NSDictionary *)saveInfo appName:(NSString *)appName {
    NSString *filePath = saveInfo[@"path"];
    NSString *fileName = saveInfo[@"name"];
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:[NSString stringWithFormat:@"%@ - %@", appName, fileName]
                                                                   message:@"Game Save Actions:"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Backup Save Slot"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self backupGameSave:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Validate Save"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self validateGameSave:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Open in Hex Viewer"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self openHexViewer:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Backup"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self backupFile:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showFileOptions:(NSDictionary *)fileInfo {
    NSString *filePath = fileInfo[@"path"];
    NSString *fileName = fileInfo[@"name"];
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:fileName
                                                                   message:@"Select action:"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Open Binary Viewer"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self openHexViewer:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Backup Now"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self backupFile:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Export"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self showExportOptions:fileInfo];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"View Backups"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self showFileBackups:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"File Info"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self showFileInfo:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        UITableViewCell *cell = [self.tableView cellForRowAtIndexPath:[NSIndexPath indexPathForRow:[self.filteredApps indexOfObject:fileInfo] inSection:0]];
        alert.popoverPresentationController.sourceView = cell;
        alert.popoverPresentationController.sourceRect = cell.bounds;
    }
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)openAdvancedPlistEditor:(NSDictionary *)fileInfo {
    NSString *filePath = fileInfo[@"path"];
    
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;
        NSData *data = [[ISFileManager shared] readFileAtPath:filePath error:&error];
        BOOL isBinary = [[ISFileManager shared] isBinaryPlist:data];
        id plistObject = [[ISFileManager shared] parsePlistData:data error:&error];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            if (error) {
                [self showAlertWithTitle:@"Error" message:error.localizedDescription];
                return;
            }
            
            if (!plistObject) {
                [self showAlertWithTitle:@"Error" message:@"Failed to parse plist file"];
                return;
            }
            
            ISPlistEditorViewController *editorVC = [[ISPlistEditorViewController alloc] initWithPlistObject:plistObject
                                                                                                    filePath:filePath
                                                                                                    isBinary:isBinary];
            [self.navigationController pushViewController:editorVC animated:YES];
        });
    });
}

- (void)openHexViewer:(NSString *)filePath {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;
        NSData *data = [[ISFileManager shared] readFileAtPath:filePath error:&error];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            if (error) {
                [self showAlertWithTitle:@"Error" message:error.localizedDescription];
                return;
            }
            
            if (!data) {
                [self showAlertWithTitle:@"Error" message:@"Failed to read file"];
                return;
            }
            
            ISHexViewController *hexVC = [[ISHexViewController alloc] initWithData:data filePath:filePath];
            [self.navigationController pushViewController:hexVC animated:YES];
        });
    });
}

- (void)openFileInHexEditor:(NSString *)filePath {
    if (![[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
        [self showAlertWithTitle:@"Error" message:@"File does not exist"];
        return;
    }
    
    [self openHexViewer:filePath];
}

- (void)openFileInPlistEditor:(NSString *)filePath {
    if (![[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
        [self showAlertWithTitle:@"Error" message:@"File does not exist"];
        return;
    }
    
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;
        NSData *data = [[NSData alloc] initWithContentsOfFile:filePath];
        BOOL isBinary = [[ISFileManager shared] isBinaryPlist:data];
        id plistObject = [[ISFileManager shared] parsePlistData:data error:&error];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            if (error || !plistObject) {
                [self showAlertWithTitle:@"Error" message:@"File is not a valid plist"];
                return;
            }
            
            ISPlistEditorViewController *editorVC = [[ISPlistEditorViewController alloc] initWithPlistObject:plistObject
                                                                                                    filePath:filePath
                                                                                                    isBinary:isBinary];
            [self.navigationController pushViewController:editorVC animated:YES];
        });
    });
}

- (void)openDatabaseInBrowser:(NSString *)dbPath {
    if (![[NSFileManager defaultManager] fileExistsAtPath:dbPath]) {
        [self showAlertWithTitle:@"Error" message:@"Database file does not exist"];
        return;
    }
    
    // Check if it's a SQLite database
    NSData *header = [NSData dataWithContentsOfFile:dbPath];
    if (header.length < 16) {
        [self showAlertWithTitle:@"Error" message:@"File is not a valid SQLite database"];
        return;
    }
    
    const char *bytes = (const char *)header.bytes;
    if (strncmp(bytes, "SQLite format 3", 15) != 0) {
        [self showAlertWithTitle:@"Error" message:@"File is not a valid SQLite database"];
        return;
    }
    
    ISSQLiteBrowser *browser = [[ISSQLiteBrowser alloc] initWithDatabasePath:dbPath];
    [self.navigationController pushViewController:browser animated:YES];
}

- (void)compareTwoFiles:(NSString *)file1 and:(NSString *)file2 {
    if (![[NSFileManager defaultManager] fileExistsAtPath:file1] || 
        ![[NSFileManager defaultManager] fileExistsAtPath:file2]) {
        [self showAlertWithTitle:@"Error" message:@"One or both files do not exist"];
        return;
    }
    
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSData *data1 = [NSData dataWithContentsOfFile:file1];
        NSData *data2 = [NSData dataWithContentsOfFile:file2];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            BOOL areEqual = [data1 isEqualToData:data2];
            NSString *message = areEqual ? @"Files are identical" : @"Files are different";
            
            if (!areEqual) {
                message = [NSString stringWithFormat:@"%@\nFile 1: %lu bytes\nFile 2: %lu bytes",
                          message, (unsigned long)data1.length, (unsigned long)data2.length];
            }
            
            [self showAlertWithTitle:@"File Comparison" message:message];
        });
    });
}

- (void)encryptFileTool {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Encrypt File"
                                                                   message:@"Enter file path and password:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"File path to encrypt";
    }];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Encryption password";
        textField.secureTextEntry = YES;
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Encrypt"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *filePath = alert.textFields[0].text;
        NSString *password = alert.textFields[1].text;
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
            [self showAlertWithTitle:@"Error" message:@"File does not exist"];
            return;
        }
        
        [self encryptFile:filePath withPassword:password];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)decryptFileTool {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Decrypt File"
                                                                   message:@"Enter encrypted file path and password:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Encrypted file path";
    }];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Decryption password";
        textField.secureTextEntry = YES;
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Decrypt"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *filePath = alert.textFields[0].text;
        NSString *password = alert.textFields[1].text;
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
            [self showAlertWithTitle:@"Error" message:@"File does not exist"];
            return;
        }
        
        [self decryptFile:filePath withPassword:password];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)generateHashTool {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Generate Hash"
                                                                   message:@"Enter file path:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"File path";
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Generate"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *filePath = alert.textFields.firstObject.text;
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
            [self showAlertWithTitle:@"Error" message:@"File does not exist"];
            return;
        }
        
        [self generateFileHash:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)encryptFile:(NSString *)filePath withPassword:(NSString *)password {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;
        NSString *destPath = [filePath stringByAppendingString:@".enc"];
        
        BOOL success = [[ISFileManager shared] encryptFile:filePath toPath:destPath password:password error:&error];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            if (success) {
                [self showAlertWithTitle:@"Success" 
                                 message:[NSString stringWithFormat:@"File encrypted successfully\nSaved to: %@", destPath]];
            } else {
                [self showAlertWithTitle:@"Error" message:error.localizedDescription ?: @"Encryption failed"];
            }
        });
    });
}

- (void)decryptFile:(NSString *)filePath withPassword:(NSString *)password {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;
        NSString *destPath = [filePath stringByReplacingOccurrencesOfString:@".enc" withString:@".dec"];
        
        BOOL success = [[ISFileManager shared] decryptFile:filePath toPath:destPath password:password error:&error];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            if (success) {
                [self showAlertWithTitle:@"Success" 
                                 message:[NSString stringWithFormat:@"File decrypted successfully\nSaved to: %@", destPath]];
            } else {
                [self showAlertWithTitle:@"Error" message:error.localizedDescription ?: @"Decryption failed"];
            }
        });
    });
}

- (void)generateFileHash:(NSString *)filePath {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *md5 = [[ISFileManager shared] getFileChecksum:filePath algorithm:@"MD5"];
        NSString *sha1 = [[ISFileManager shared] getFileChecksum:filePath algorithm:@"SHA1"];
        NSString *sha256 = [[ISFileManager shared] getFileChecksum:filePath algorithm:@"SHA256"];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            NSString *message = [NSString stringWithFormat:@"File: %@\n\n"
                                @"MD5: %@\n\n"
                                @"SHA1: %@\n\n"
                                @"SHA256: %@",
                                [filePath lastPathComponent],
                                md5 ?: @"Error",
                                sha1 ?: @"Error",
                                sha256 ?: @"Error"];
            
            [self showAlertWithTitle:@"File Hashes" message:message];
        });
    });
}

- (void)startCustomPortServer {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Custom Port"
                                                                   message:@"Enter port number (1024-65535):"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Port number";
        textField.keyboardType = UIKeyboardTypeNumberPad;
        textField.text = @"8080";
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Start"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *portString = alert.textFields.firstObject.text;
        int port = [portString intValue];
        
        if (port < 1024 || port > 65535) {
            [self showAlertWithTitle:@"Error" message:@"Port must be between 1024 and 65535"];
            return;
        }
        
        if ([[ISWebDAVServer shared] startServerOnPort:port]) {
            NSString *url = [[ISWebDAVServer shared] serverURL];
            [self showAlertWithTitle:@"Server Started" 
                             message:[NSString stringWithFormat:@"Server started at:\n%@\n\nUse WebDAV client to connect.", url]];
        } else {
            [self showAlertWithTitle:@"Error" message:@"Failed to start server"];
        }
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)manageSaveSlots {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Manage Save Slots"
                                                                   message:@"Enter game save file path:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Game save file path";
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Manage"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *savePath = alert.textFields.firstObject.text;
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:savePath]) {
            [self showAlertWithTitle:@"Error" message:@"Save file does not exist"];
            return;
        }
        
        [self showSaveSlotManager:savePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)validateSaveFile {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Validate Save File"
                                                                   message:@"Enter save file path:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Save file path";
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Validate"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *savePath = alert.textFields.firstObject.text;
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:savePath]) {
            [self showAlertWithTitle:@"Error" message:@"Save file does not exist"];
            return;
        }
        
        BOOL isValid = [[ISGameSaveManager shared] validateSaveFile:savePath];
        NSString *message = isValid ? @"Save file appears to be valid" : @"Save file may be corrupted or invalid";
        
        [self showAlertWithTitle:@"Validation Result" message:message];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showSaveSlotManager:(NSString *)savePath {
    NSArray *slots = [[ISGameSaveManager shared] getSaveSlotsForGame:[savePath lastPathComponent]];
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Save Slots"
                                                                   message:[NSString stringWithFormat:@"Found %lu save slots", (unsigned long)slots.count]
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    for (int i = 1; i <= 10; i++) {
        NSString *title = [NSString stringWithFormat:@"Slot %d", i];
        
        // Check if slot has backup
        BOOL hasBackup = NO;
        for (NSDictionary *slot in slots) {
            if ([slot[@"slot"] intValue] == i) {
                hasBackup = YES;
                NSDate *backupDate = slot[@"backupDate"];
                NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
                [formatter setDateFormat:@"MMM dd, HH:mm"];
                title = [NSString stringWithFormat:@"Slot %d (Backup: %@)", i, [formatter stringFromDate:backupDate]];
                break;
            }
        }
        
        UIAlertAction *action = [UIAlertAction actionWithTitle:title
                                                         style:UIAlertActionStyleDefault
                                                       handler:^(UIAlertAction *action) {
            [self manageSaveSlot:savePath slot:i hasBackup:hasBackup];
        }];
        
        if (hasBackup) {
            [action setValue:[ISTheme successColor] forKey:@"titleTextColor"];
        }
        
        [alert addAction:action];
    }
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)manageSaveSlot:(NSString *)savePath slot:(int)slot hasBackup:(BOOL)hasBackup {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:[NSString stringWithFormat:@"Slot %d", slot]
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Backup to this slot"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        BOOL success = [[ISGameSaveManager shared] backupGameSave:savePath slot:slot];
        NSString *message = success ? @"Save backed up successfully" : @"Backup failed";
        [self showAlertWithTitle:@"Backup Result" message:message];
    }]];
    
    if (hasBackup) {
        [alert addAction:[UIAlertAction actionWithTitle:@"Restore from this slot"
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            BOOL success = [[ISGameSaveManager shared] restoreGameSave:savePath slot:slot];
            NSString *message = success ? @"Save restored successfully" : @"Restore failed";
            [self showAlertWithTitle:@"Restore Result" message:message];
        }]];
    }
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)backupGameSave:(NSString *)savePath {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Backup Game Save"
                                                                   message:@"Select backup slot:"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    for (int i = 1; i <= 5; i++) {
        [alert addAction:[UIAlertAction actionWithTitle:[NSString stringWithFormat:@"Slot %d", i]
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            BOOL success = [[ISGameSaveManager shared] backupGameSave:savePath slot:i];
            NSString *message = success ? @"Game save backed up successfully" : @"Backup failed";
            [self showAlertWithTitle:@"Backup Result" message:message];
        }]];
    }
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)validateGameSave:(NSString *)savePath {
    BOOL isValid = [[ISGameSaveManager shared] validateSaveFile:savePath];
    NSString *message = isValid ? @"Game save appears to be valid" : @"Game save may be corrupted or invalid";
    
    [self showAlertWithTitle:@"Validation Result" message:message];
}

- (void)showExportOptions:(NSDictionary *)fileInfo {
    NSString *filePath = fileInfo[@"path"];
    NSString *fileName = fileInfo[@"name"];
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Export Options"
                                                                   message:@"How do you want to export the file?"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Save to HDD/Device Storage"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self exportToHDD:filePath fileName:fileName];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Share via Files App"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self exportViaShare:filePath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Encrypt & Export"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self encryptAndExport:filePath fileName:fileName];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)exportToHDD:(NSString *)filePath fileName:(NSString *)fileName {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;
        NSData *data = [[NSFileManager defaultManager] contentsAtPath:filePath];
        
        if (!data) {
            data = [[ISFileManager shared] readFileAtPath:filePath error:&error];
        }
        
        BOOL success = NO;
        if (data) {
            success = [[ISFileManager shared] exportToHDD:data fileName:fileName error:&error];
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            if (success) {
                [self showAlertWithTitle:@"Export Successful" 
                                 message:@"File saved to /var/mobile/Documents/Exports"];
            } else {
                [self showAlertWithTitle:@"Export Failed" 
                                 message:error.localizedDescription ?: @"Unknown error"];
            }
        });
    });
}

- (void)exportViaShare:(NSString *)filePath {
    NSURL *fileURL = [NSURL fileURLWithPath:filePath];
    
    UIActivityViewController *activityVC = [[UIActivityViewController alloc] initWithActivityItems:@[fileURL]
                                                                             applicationActivities:nil];
    
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        activityVC.popoverPresentationController.sourceView = self.view;
        activityVC.popoverPresentationController.sourceRect = CGRectMake(self.view.bounds.size.width/2, self.view.bounds.size.height/2, 1, 1);
    }
    
    [self presentViewController:activityVC animated:YES completion:nil];
}

- (void)encryptAndExport:(NSString *)filePath fileName:(NSString *)fileName {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Encrypt & Export"
                                                                   message:@"Enter encryption password:"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Password";
        textField.secureTextEntry = YES;
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Encrypt & Export"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *password = alert.textFields.firstObject.text;
        [self performEncryptAndExport:filePath fileName:fileName password:password];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)performEncryptAndExport:(NSString *)filePath fileName:(NSString *)fileName password:(NSString *)password {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;
        NSData *data = [[NSFileManager defaultManager] contentsAtPath:filePath];
        
        if (!data) {
            data = [[ISFileManager shared] readFileAtPath:filePath error:&error];
        }
        
        if (!data) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.loadingIndicator stopAnimating];
                [self showAlertWithTitle:@"Error" message:@"Failed to read file"];
            });
            return;
        }
        
        // Encrypt data
        NSData *encryptedData = [ISEncryptionManager encryptData:data password:password];
        if (!encryptedData) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.loadingIndicator stopAnimating];
                [self showAlertWithTitle:@"Error" message:@"Encryption failed"];
            });
            return;
        }
        
        // Export encrypted data
        BOOL success = [[ISFileManager shared] exportToHDD:encryptedData 
                                                   fileName:[fileName stringByAppendingString:@".enc"] 
                                                      error:&error];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            if (success) {
                [self showAlertWithTitle:@"Export Successful" 
                                 message:@"Encrypted file saved to /var/mobile/Documents/Exports"];
            } else {
                [self showAlertWithTitle:@"Export Failed" 
                                 message:error.localizedDescription ?: @"Unknown error"];
            }
        });
    });
}

- (void)backupFile:(NSString *)filePath {
    [self.loadingIndicator startAnimating];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;
        BOOL success = [[ISFileManager shared] backupFile:filePath error:&error];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.loadingIndicator stopAnimating];
            
            if (success) {
                [self showAlertWithTitle:@"Success" message:@"Backup created"];
            } else {
                [self showAlertWithTitle:@"Error" message:error.localizedDescription ?: @"Backup failed"];
            }
        });
    });
}

- (void)showFileBackups:(NSString *)filePath {
    NSArray *backups = [[ISFileManager shared] getBackupsForFile:filePath];
    
    if (backups.count == 0) {
        [self showAlertWithTitle:@"No Backups" message:@"No backups found for this file"];
        return;
    }
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Select Backup"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    for (NSDictionary *backup in backups) {
        NSString *name = backup[@"name"];
        [alert addAction:[UIAlertAction actionWithTitle:name
                                                  style:UIAlertActionStyleDefault
                                                handler:^(UIAlertAction *action) {
            [self showBackupOptions:backup originalPath:filePath];
        }]];
    }
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showBackupOptions:(NSDictionary *)backup originalPath:(NSString *)originalPath {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Backup Options"
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Restore"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self restoreBackup:backup[@"path"] toPath:originalPath];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Delete"
                                              style:UIAlertActionStyleDestructive
                                            handler:^(UIAlertAction *action) {
        [self deleteBackup:backup[@"path"]];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)restoreBackup:(NSString *)backupPath toPath:(NSString *)originalPath {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Restore Backup"
                                                                   message:@"Are you sure you want to restore this backup? Current file will be backed up first."
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Restore"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [self.loadingIndicator startAnimating];
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            NSError *error = nil;
            BOOL success = [[ISFileManager shared] restoreBackup:backupPath toPath:originalPath error:&error];
            
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.loadingIndicator stopAnimating];
                
                if (success) {
                    [self showAlertWithTitle:@"Success" message:@"Backup restored"];
                } else {
                    [self showAlertWithTitle:@"Error" message:error.localizedDescription ?: @"Restore failed"];
                }
            });
        });
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)deleteBackup:(NSString *)backupPath {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Delete Backup"
                                                                   message:@"Are you sure you want to delete this backup?"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Delete"
                                              style:UIAlertActionStyleDestructive
                                            handler:^(UIAlertAction *action) {
        NSError *error = nil;
        BOOL success = [[NSFileManager defaultManager] removeItemAtPath:backupPath error:&error];
        
        if (success) {
            [self showAlertWithTitle:@"Success" message:@"Backup deleted"];
        } else {
            [self showAlertWithTitle:@"Error" message:error.localizedDescription ?: @"Delete failed"];
        }
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showFileInfo:(NSString *)filePath {
    NSDictionary *info = [[ISFileManager shared] getFileInfo:filePath];
    
    if (!info) {
        [self showAlertWithTitle:@"Error" message:@"Failed to get file info"];
        return;
    }
    
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    
    NSString *sizeStr = [NSByteCountFormatter stringFromByteCount:[info[@"size"] longLongValue]
                                                        countStyle:NSByteCountFormatterCountStyleFile];
    
    NSString *message = [NSString stringWithFormat:@"Name: %@\n"
                        @"Path: %@\n"
                        @"Size: %@\n"
                        @"Type: %@\n"
                        @"Created: %@\n"
                        @"Modified: %@\n"
                        @"Permissions: %@",
                        info[@"name"],
                        info[@"path"],
                        sizeStr,
                        info[@"fileType"],
                        [formatter stringFromDate:info[@"created"]],
                        [formatter stringFromDate:info[@"modified"]],
                        info[@"permissions"]];
    
    [self showAlertWithTitle:@"File Information" message:message];
}

- (void)favoriteButtonTapped:(UIButton *)sender {
    NSInteger index = sender.tag;
    ISAppInfo *appInfo = self.filteredApps[index];
    
    if (![self.favorites containsObject:appInfo.dataPath]) {
        [self.favorites addObject:appInfo.dataPath];
        [self saveFavorites];
        [self showAlertWithTitle:@"Added to Favorites" message:@"App added to favorites"];
    } else {
        [self.favorites removeObject:appInfo.dataPath];
        [self saveFavorites];
        [self showAlertWithTitle:@"Removed from Favorites" message:@"App removed from favorites"];
    }
}

- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText {
    if (searchText.length == 0) {
        self.filteredApps = self.apps;
    } else {
        UISegmentedControl *segmentControl = (UISegmentedControl *)self.navigationItem.titleView;
        
        if (segmentControl.selectedSegmentIndex == 0) {
            // Search in apps
            NSPredicate *predicate = [NSPredicate predicateWithFormat:@"appName CONTAINS[cd] %@ OR bundleId CONTAINS[cd] %@", searchText, searchText];
            self.filteredApps = [self.apps filteredArrayUsingPredicate:predicate];
        } else if (segmentControl.selectedSegmentIndex == 1 || segmentControl.selectedSegmentIndex == 2) {
            // Search in files or favorites
            NSPredicate *predicate = [NSPredicate predicateWithFormat:@"name CONTAINS[cd] %@", searchText];
            self.filteredApps = [self.apps filteredArrayUsingPredicate:predicate];
        }
    }
    
    [self.tableView reloadData];
    self.emptyLabel.hidden = (self.filteredApps.count > 0);
}

- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar {
    [searchBar resignFirstResponder];
}

- (void)showAlertWithTitle:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}
@end

// MARK: - App Delegate
@interface ISAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UINavigationController *navigationController;
@property (nonatomic, strong) UIView *whiteSplashView;
@end

@implementation ISAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    [ISLogger setup];
    [ISLogger log:@"iSaveTool launched"];
    
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.backgroundColor = [UIColor whiteColor];
    
    self.whiteSplashView = [[UIView alloc] initWithFrame:self.window.bounds];
    self.whiteSplashView.backgroundColor = [UIColor whiteColor];
    [self.window addSubview:self.whiteSplashView];
    
    ISMainViewController *mainVC = [[ISMainViewController alloc] init];
    self.navigationController = [[UINavigationController alloc] initWithRootViewController:mainVC];
    
    self.navigationController.navigationBar.translucent = YES;
    self.navigationController.navigationBar.tintColor = [ISTheme accentColor];
    
    self.window.rootViewController = self.navigationController;
    [self.window makeKeyAndVisible];
    
    [self performSplashAnimation];
    
    return YES;
}

- (void)performSplashAnimation {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [UIView animateWithDuration:1.8
                              delay:0
                            options:UIViewAnimationOptionCurveEaseInOut
                         animations:^{
            self.whiteSplashView.alpha = 0;
        } completion:^(BOOL finished) {
            [self.whiteSplashView removeFromSuperview];
            self.whiteSplashView = nil;
        }];
    });
}

- (void)applicationWillResignActive:(UIApplication *)application {
    [ISLogger log:@"App will resign active"];
    [[ISAudioManager shared] applicationWillResignActive];
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    [ISLogger log:@"App entered background"];
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    [ISLogger log:@"App will enter foreground"];
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    [ISLogger log:@"App became active"];
    [[ISAudioManager shared] applicationDidBecomeActive];
}

- (void)applicationWillTerminate:(UIApplication *)application {
    [ISLogger log:@"App terminating"];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([ISAppDelegate class]));
    }
}