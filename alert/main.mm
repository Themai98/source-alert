// prj gốc https://github.com/x2niosvn/Custom-application-startup-notification-Theos
// Chỉnh sửa và share tại https://t.me/dvcipaios

#import <UIKit/UIKit.h>
#define UIColorFromHEX(rgbValue) [UIColor \
colorWithRed:((float)((rgbValue & 0xFF0000) >> 16))/255.0 \
green:((float)((rgbValue & 0xFF00) >> 8))/255.0 \
blue:((float)(rgbValue & 0xFF))/255.0 alpha:1.0]
#import "SCLAlertView/SCLAlertView.h"

SCLAlertView *alert;

@interface Game.Framework : NSObject
@end

@implementation NguyenNamFramework

static NguyenNamFramework *active;

+ (void)load {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        alert = [[SCLAlertView alloc] initWithNewWindow];
        active = [NguyenNamFramework new];
        [active start];
    });
}



- (void)start {
    [self setupLogoView];
    [self setupAlertView];
}

// thông báo khi khởi động
- (void)setupAlertView {
    alert.shouldDismissOnTapOutside = NO;
    alert.customViewColor = UIColorFromHEX(0x474747);
    alert.showAnimationType = SCLAlertViewShowAnimationSlideInToCenter;
    alert.backgroundType = SCLAlertViewBackgroundBlur;
    alert.cornerRadius = 20.0f;
    alert.backgroundViewColor = UIColorFromHEX(0x302d26);
    
// nút 1
    [alert addButton:@"Telegram Themai98 " actionBlock:^(void) {
        [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://t.me/themai98"]
                                           options:@{}
                                 completionHandler:nil];
    }];
///

// nút 2
    [alert addButton:@"Website Tôi" actionBlock:^(void) {
        [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://themai98.github.io/home"]
                                           options:@{}
                                 completionHandler:nil];
    }];
//

// nút 3
    [alert addButton:@"Thanks" actionBlock:^(void) {}];
//
    
    NSData *data = [NSData dataWithContentsOfURL:[NSURL URLWithString:@"https://gcs.tripi.vn/public-tripi/tripi-feed/img/474353AXw/avatar-shin-dang-yeu-nhat_014817355.jpg"]]; // logo
    UIImage *customAlertImage = [UIImage imageWithData:data];
    
// text info
 [alert showCustom:alert image:customAlertImage color:[UIColor clearColor] title:@"Themai98 IOS " subTitle:@"Hack Games & Programs iOS" closeButtonTitle:nil duration:9999999999.0f];
}

- (void)setupLogoView {
    UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
    if (!keyWindow) {
        return;
    }
    
    UIImageView *logoView = [[UIImageView alloc] initWithFrame:CGRectMake(10, 30, 50, 50)];
    logoView.layer.cornerRadius = 25;
    logoView.clipsToBounds = YES;
    logoView.contentMode = UIViewContentModeScaleAspectFill;
    
    NSData *data = [NSData dataWithContentsOfURL:[NSURL URLWithString:@"https://gcs.tripi.vn/public-tripi/tripi-feed/img/474353AXw/avatar-shin-dang-yeu-nhat_014817355.jpg"]]; // icon
    UIImage *logoImage = [UIImage imageWithData:data];
    logoView.image = logoImage;
    
    // Add pan gesture to enable dragging
    UIPanGestureRecognizer *panGesture = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePanGesture:)];
    [logoView addGestureRecognizer:panGesture];

    // Add tap gesture to show alert
    UITapGestureRecognizer *tapGesture = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(handleTapGesture:)];
    [logoView addGestureRecognizer:tapGesture];
    
    logoView.userInteractionEnabled = YES;
    
    [keyWindow addSubview:logoView];
}

- (void)handlePanGesture:(UIPanGestureRecognizer *)gestureRecognizer {
    UIView *piece = [gestureRecognizer view];
    CGPoint translation = [gestureRecognizer translationInView:[piece superview]];
    
    if ([gestureRecognizer state] == UIGestureRecognizerStateBegan || [gestureRecognizer state] == UIGestureRecognizerStateChanged) {
        [piece setCenter:CGPointMake([piece center].x + translation.x, [piece center].y + translation.y)];
        [gestureRecognizer setTranslation:CGPointZero inView:[piece superview]];
    }
}


// thông báo khi click vào icon
- (void)handleTapGesture:(UITapGestureRecognizer *)gestureRecognizer {
    // Khởi tạo alert mới
    SCLAlertView *newAlert = [[SCLAlertView alloc] initWithNewWindow];
    
    newAlert.shouldDismissOnTapOutside = NO;
    newAlert.customViewColor = UIColorFromHEX(0x474747);
    newAlert.showAnimationType = SCLAlertViewShowAnimationSlideInToCenter;
    newAlert.backgroundType = SCLAlertViewBackgroundBlur;
    newAlert.cornerRadius = 20.0f;
    newAlert.backgroundViewColor = UIColorFromHEX(0x302d26); 

    [newAlert addButton:@"Telegram Themai98 " actionBlock:^(void) {
        [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://t.me/themai98"]
                                           options:@{}
                                 completionHandler:nil];
    }];
    [newAlert addButton:@"Website Tôi" actionBlock:^(void) {
        [[UIApplication sharedApplication] openURL:[NSURL URLWithString:@"https://themai98.github.io/home"]
                                           options:@{}
                                 completionHandler:nil];
    }];
    [newAlert addButton:@"Thanks" actionBlock:^(void) {}];

    NSData *data = [NSData dataWithContentsOfURL:[NSURL URLWithString:@"https://gcs.tripi.vn/public-tripi/tripi-feed/img/474353AXw/avatar-shin-dang-yeu-nhat_014817355.jpg"]];
    UIImage *customAlertImage = [UIImage imageWithData:data];

    [newAlert showCustom:newAlert
                   image:customAlertImage
                   color:[UIColor clearColor]
                   title:@"Themai98 IOS "
                subTitle:@"Hack Games & Programs iOS"
         closeButtonTitle:nil
                 duration:9999999999.0f];
}

@end
