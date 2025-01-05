#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

// Khai báo extern để có thể truy cập từ APIKey.a
extern NSString * const __kHashDefaultValue;
extern NSString * const __notificationTitle;
extern NSString * const __notificationTitlenoidung;
extern NSString * const __contact;
extern NSString * const __Confirm;
extern NSString * const __Input;

@interface LDVQuang : NSObject

- (void) loading:(void (^)(void))execute paidBlock:(void (^)(void))paidBlock; // Thêm paidBlock

@property (nonatomic, assign, readonly) BOOL isKeyValidated; // Thêm khai báo isKeyValidated
@end