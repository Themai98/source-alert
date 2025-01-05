#ifndef Language_h
#define Language_h

#include <string>
#include <map>

enum class Language {
    Vietnamese,
    English,
    Taiwanese
};

enum class LocalizedStringKey {
    UnlockSkin,
    LanguageSetting,
    SelectLanguage,
    Vietnamese,
    English,
    Taiwanese,
    MainHack,
    Skin,
    Info,
    Esp,
    AnHack,
    Hackmap,
    LockCamera,
    StartAIM,
    AimFeature,
    CustomizeYourView,
    ShowCD,
    SaveSetting,
    UseSetting,
    ResetSetting,
    AimTrigger,
    DrawAimedObject,
    LowestHealthPercent,
    LowestHealth,
    NearestDistance,
    ClosestToRay,
    No,
    Always,
    WhenWatching,
    Contact,
    Telegram,
    Admin,
    HackInformation,
    HackName,
    Version,
    Features,
    Advertisement,
    BuyServerKey
};

void LoadLanguage(Language language);

extern std::map<LocalizedStringKey, std::string> localizedStrings;

extern Language currentLanguage;

#endif /* Language_h */