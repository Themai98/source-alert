#include "Language.h"

std::map<LocalizedStringKey, std::string> localizedStrings;

Language currentLanguage;

void LoadLanguage(Language language) {
    localizedStrings.clear();

    switch (language) {
        case Language::Vietnamese:
            localizedStrings[LocalizedStringKey::UnlockSkin] = "Mở Khóa Skin";
              localizedStrings[LocalizedStringKey::LanguageSetting] = "Language Setting";
            localizedStrings[LocalizedStringKey::SelectLanguage] = "Chọn Ngôn ngữ";
            localizedStrings[LocalizedStringKey::Vietnamese] = "Tiếng Việt";
            localizedStrings[LocalizedStringKey::English] = "English";
            localizedStrings[LocalizedStringKey::Taiwanese] = "台灣";
            localizedStrings[LocalizedStringKey::MainHack] = "Cài Đặt";
            localizedStrings[LocalizedStringKey::Skin] = "Mở Khóa";
            localizedStrings[LocalizedStringKey::Info] = "Mua";
            localizedStrings[LocalizedStringKey::Hackmap] = "Map Sáng";
            localizedStrings[LocalizedStringKey::LockCamera] = "Khóa Camera";
            localizedStrings[LocalizedStringKey::StartAIM] = "Aim bot";
            localizedStrings[LocalizedStringKey::AimFeature] = "Chế Độ";
            localizedStrings[LocalizedStringKey::CustomizeYourView] = "Camera Slider Value";
            localizedStrings[LocalizedStringKey::ShowCD] = "Hiển thị CD";
            localizedStrings[LocalizedStringKey::SaveSetting] = "Lưu";
            localizedStrings[LocalizedStringKey::UseSetting] = "Sử Dụng";
            localizedStrings[LocalizedStringKey::ResetSetting] = "Đặt Lại";
            localizedStrings[LocalizedStringKey::AimTrigger] = "Mục Tiêu";
            localizedStrings[LocalizedStringKey::DrawAimedObject] = "Tia Laser";
            localizedStrings[LocalizedStringKey::LowestHealthPercent] = "Máu % thấp nhất";
            localizedStrings[LocalizedStringKey::LowestHealth] = "Máu thấp nhất";
            localizedStrings[LocalizedStringKey::NearestDistance] = "Khoảng cách gần nhất";
            localizedStrings[LocalizedStringKey::ClosestToRay] = "Gần tia Laser nhất";
            localizedStrings[LocalizedStringKey::No] = "Không Hiển Thị";
            localizedStrings[LocalizedStringKey::Always] = "Luôn Luôn Cho Phép";
            localizedStrings[LocalizedStringKey::WhenWatching] = "Khi Được Chọn";
            localizedStrings[LocalizedStringKey::Contact] = "Liên Hệ Tôi";
            localizedStrings[LocalizedStringKey::Telegram] = "Telegram: @modcheat70";
            localizedStrings[LocalizedStringKey::Admin] = "Custom by: Modcheat";
            localizedStrings[LocalizedStringKey::HackInformation] = "Thông Tin Phiên Bản";
            localizedStrings[LocalizedStringKey::HackName] = "Tên Menu: Auto Update All Server All Version";
            localizedStrings[LocalizedStringKey::Version] = "Phiên Bản: VIP+";
            localizedStrings[LocalizedStringKey::Features] = "Chức Năng: Full ESP, Aimbot, Unlock Skin";
            localizedStrings[LocalizedStringKey::Advertisement] = "Khác";
            localizedStrings[LocalizedStringKey::BuyServerKey] = "Thuê hack liên hệ mình";
            
            localizedStrings[LocalizedStringKey::Esp] = "Chế Độ";
           localizedStrings[LocalizedStringKey::AnHack] = "Chế Độ Streamer";

            break;
        case Language::English:
            localizedStrings[LocalizedStringKey::UnlockSkin] = "Unlock Skin";
            
            localizedStrings[LocalizedStringKey::LanguageSetting] = "Language Setting";
            localizedStrings[LocalizedStringKey::SelectLanguage] = "Select Language";
            localizedStrings[LocalizedStringKey::Vietnamese] = "Tiếng Việt";
            localizedStrings[LocalizedStringKey::English] = "English";
            localizedStrings[LocalizedStringKey::Taiwanese] = "台灣";
            localizedStrings[LocalizedStringKey::MainHack] = "Main";
            localizedStrings[LocalizedStringKey::Skin] = "Unlock";
            localizedStrings[LocalizedStringKey::Info] = "Buy";
            localizedStrings[LocalizedStringKey::Hackmap] = "Hack Map";
            localizedStrings[LocalizedStringKey::LockCamera] = "Lock Camera";
            localizedStrings[LocalizedStringKey::StartAIM] = "Start AimBot";
            localizedStrings[LocalizedStringKey::AimFeature] = "AimBot Feature";
            localizedStrings[LocalizedStringKey::CustomizeYourView] = "Camera Slider";
            localizedStrings[LocalizedStringKey::ShowCD] = "Show CD Skill";
            localizedStrings[LocalizedStringKey::SaveSetting] = "Save Setting";
            localizedStrings[LocalizedStringKey::UseSetting] = "Use Setting";
            localizedStrings[LocalizedStringKey::ResetSetting] = "Reset Setting";
            localizedStrings[LocalizedStringKey::AimTrigger] = "Aim Settings";
            localizedStrings[LocalizedStringKey::DrawAimedObject] = "Show Laser";
            localizedStrings[LocalizedStringKey::LowestHealthPercent] = "Lowest Health %";
            localizedStrings[LocalizedStringKey::LowestHealth] = "Lowest Health";
            localizedStrings[LocalizedStringKey::NearestDistance] = "Nearest Distance";
            localizedStrings[LocalizedStringKey::ClosestToRay] = "Closest to Ray";
            localizedStrings[LocalizedStringKey::No] = "No";
            localizedStrings[LocalizedStringKey::Always] = "Always";
            localizedStrings[LocalizedStringKey::WhenWatching] = "When Watching";
            localizedStrings[LocalizedStringKey::Contact] = "Contact";
            localizedStrings[LocalizedStringKey::Telegram] = "Telegram: @modcheat70";
            localizedStrings[LocalizedStringKey::Admin] = "ADMIN: Modcheat";
            localizedStrings[LocalizedStringKey::HackInformation] = "Hack Info";
            localizedStrings[LocalizedStringKey::HackName] = "Menu Name: Auto Update All Server All Version";
            localizedStrings[LocalizedStringKey::Version] = "Version: VIP+";
            localizedStrings[LocalizedStringKey::Features] = "Features: ESP, Aimbot, Modskin";
            localizedStrings[LocalizedStringKey::Advertisement] = "Advertisement";
            localizedStrings[LocalizedStringKey::BuyServerKey] = "Buy Key Contact Me";
            
            localizedStrings[LocalizedStringKey::Esp] = "Mode";
           localizedStrings[LocalizedStringKey::AnHack] = "Streamer mode";


            break;
        case Language::Taiwanese:
            localizedStrings[LocalizedStringKey::UnlockSkin] = "解鎖皮膚";
            
            localizedStrings[LocalizedStringKey::LanguageSetting] = "語言設定";
            localizedStrings[LocalizedStringKey::SelectLanguage] = "選擇語言";
            localizedStrings[LocalizedStringKey::Vietnamese] = "Tiếng Việt";
            localizedStrings[LocalizedStringKey::English] = "English";
            localizedStrings[LocalizedStringKey::Taiwanese] = "台灣";
            localizedStrings[LocalizedStringKey::MainHack] = "主要駭客";
            localizedStrings[LocalizedStringKey::Skin] = "皮膚";
            localizedStrings[LocalizedStringKey::Info] = "資訊";
            localizedStrings[LocalizedStringKey::Hackmap] = "駭客地圖";
            localizedStrings[LocalizedStringKey::LockCamera] = "鎖定相機";
            localizedStrings[LocalizedStringKey::StartAIM] = "開始瞄準";
            localizedStrings[LocalizedStringKey::AimFeature] = "瞄準功能";
            localizedStrings[LocalizedStringKey::CustomizeYourView] = "自定義視圖";
            localizedStrings[LocalizedStringKey::ShowCD] = "顯示CD";
            localizedStrings[LocalizedStringKey::SaveSetting] = "儲存設定";
            localizedStrings[LocalizedStringKey::UseSetting] = "使用設定";
            localizedStrings[LocalizedStringKey::ResetSetting] = "重設設定";
            localizedStrings[LocalizedStringKey::AimTrigger] = "瞄準觸發器";
            localizedStrings[LocalizedStringKey::DrawAimedObject] = "繪製瞄準對象";
            localizedStrings[LocalizedStringKey::LowestHealthPercent] = "最低生命值百分比";
            localizedStrings[LocalizedStringKey::LowestHealth] = "最低生命值";
            localizedStrings[LocalizedStringKey::NearestDistance] = "最近距離";
            localizedStrings[LocalizedStringKey::ClosestToRay] = "最靠近光線";
            localizedStrings[LocalizedStringKey::No] = "否";
            localizedStrings[LocalizedStringKey::Always] = "總是";
            localizedStrings[LocalizedStringKey::WhenWatching] = "觀看時";
            localizedStrings[LocalizedStringKey::Contact] = "聯繫方式";
            localizedStrings[LocalizedStringKey::Telegram] = "Telegram: @modcheat70";
            localizedStrings[LocalizedStringKey::Admin] = "管理員: Modcheat";
            localizedStrings[LocalizedStringKey::HackInformation] = "駭客資訊";
            localizedStrings[LocalizedStringKey::HackName] = "駭客名稱: Auto Update All Server All Version";
            localizedStrings[LocalizedStringKey::Version] = "版本: VIP+";
            localizedStrings[LocalizedStringKey::Features] = "功能: Full ESP, Aimbot, Unlock Skin";
            localizedStrings[LocalizedStringKey::Advertisement] = "廣告";
            localizedStrings[LocalizedStringKey::BuyServerKey] = "購買Server Key請聯繫管理員";
            
           localizedStrings[LocalizedStringKey::AnHack] = "流光模式";

            break;
    }
}