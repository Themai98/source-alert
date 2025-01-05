#include <MetalKit/MetalKit.h>
#include <Metal/Metal.h>
#include <iostream>
#include <UIKit/UIKit.h>
#include <vector>
#import "pthread.h"
#include <array>


#import "ImGuiDrawView.h"
#import "LoadView.h"
#import "FTNotificationIndicator.h"
#import "../imgui/imgui.h"
#import "../imgui/imgui_internal.h"
#import "../imgui/imgui_impl_metal.h"



#include "Utils/hack/monoString.h"
#include "Utils/EspManager.h"
#include "Utils/Monostring.h"
#include "Utils/Alert.h"
#include "Utils/Color.hpp"


#define kWidth  [UIScreen mainScreen].bounds.size.width
#define kHeight [UIScreen mainScreen].bounds.size.height
#define kScale [UIScreen mainScreen].scale

extern MenuInteraction* menuTouchView;
extern UIButton* InvisibleMenuButton;
extern UIButton* VisibleMenuButton;
extern UITextField* hideRecordTextfield;
extern UIView* hideRecordView;