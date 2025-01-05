#include "LoadView/Includes.h"
#import "LoadView/DTTJailbreakDetection.h"
#include <Foundation/Foundation.h>
#include <libgen.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/vm_page_size.h>
#include <unistd.h>
#include <array>
#include <deque>
#include <map>
#include <vector>
#import "imgui/Il2cpp.h" 
#import "il2cpp.h" 
#import "LoadView/Icon.h"
#import "imgui/stb_image.h"
#import "Utils/Macros.h"
#import "Utils/hack/Function.h"
#import "imgui/imgui_additional.h"
#import "imgui/bdvt.h"
#import "mahoa.h"
#import "hok/dobby.h"
#import "hok/MonoString.h"
#import "hook/hook.h"

#include <CoreFoundation/CoreFoundation.h>
#include "Utils/hack/Vector2.h"
#import "Utils/hack/Vector3.h"
#include "Utils/hack/VInt3.h"

#import "unlockskin.h" 
#include <limits>
#include "Utils/Quaternion.h"
#import <UIKit/UIKit.h>
#include <chrono>
#include "imgui/Language.h" 

#define STATIC_HOOK_CODEPAGE_SIZE PAGE_SIZE
#define STATIC_HOOK_DATAPAGE_SIZE PAGE_SIZE

typedef struct {
  uint64_t hook_vaddr;
  uint64_t hook_size;
  uint64_t code_vaddr;
  uint64_t code_size;

  uint64_t patched_vaddr;
  uint64_t original_vaddr;
  uint64_t instrument_vaddr;

  uint64_t patch_size;
  uint64_t patch_hash;

  void *target_replace;
  void *instrument_handler;
} StaticInlineHookBlock;

int dobby_create_instrument_bridge(void *targetData);

bool dobby_static_inline_hook(StaticInlineHookBlock *hookBlock, StaticInlineHookBlock *hookBlockRVA, uint64_t funcRVA,
                              void *funcData, uint64_t targetRVA, void *targetData, uint64_t InstrumentBridgeRVA,
                              void *patchBytes, int patchSize);


uint64_t va2rva(struct mach_header_64* header, uint64_t va)
{
    uint64_t rva = va;
    
    uint64_t header_vaddr = -1;
    struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *)lc;
            
            if(seg->fileoff==0 && seg->filesize>0)
            {
                if(header_vaddr != -1) {
                    return 0;
                }
                header_vaddr = seg->vmaddr;
            }
        }
        
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(header_vaddr != -1) {
        rva -= header_vaddr;
    }
    
    return rva;
}

void* rva2data(struct mach_header_64* header, uint64_t rva)
{
    uint64_t header_vaddr = -1;
    struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *)lc;
            
            if(seg->fileoff==0 && seg->filesize>0)
            {
                if(header_vaddr != -1) {
                    return NULL;
                }
                header_vaddr = seg->vmaddr;
            }
        }
        
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(header_vaddr != -1) {
        rva += header_vaddr;
    }
    
    lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {

        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *) lc;
            
            uint64_t seg_vmaddr_start = seg->vmaddr;
            uint64_t seg_vmaddr_end   = seg_vmaddr_start + seg->vmsize;
            if ((uint64_t)rva >= seg_vmaddr_start && (uint64_t)rva < seg_vmaddr_end)
            {
              uint64_t offset = (uint64_t)rva - seg_vmaddr_start;
              if (offset > seg->filesize) {
                return NULL;
              }
              return (void*)((uint64_t)header + seg->fileoff + offset);
            }
        }

        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    return NULL;
}

NSMutableData* load_macho_data(NSString* path)
{
    NSMutableData* macho = [NSMutableData dataWithContentsOfFile:path];
    if(!macho) return nil;
    
    UInt32 magic = *(uint32_t*)macho.mutableBytes;
    if(magic==FAT_CIGAM)
    {
        struct fat_header* fathdr = (struct fat_header*)macho.mutableBytes;
        struct fat_arch* archdr = (struct fat_arch*)((UInt64)fathdr + sizeof(*fathdr));
        if(NXSwapLong(fathdr->nfat_arch) != 1) {
            return nil;
        }
        
        if(NXSwapLong(archdr->cputype) != CPU_TYPE_ARM64 || archdr->cpusubtype!=0) {
            return nil;
        }
        macho = [NSMutableData dataWithData:
                 [macho subdataWithRange:NSMakeRange(NXSwapLong(archdr->offset), NXSwapLong(archdr->size))]];
        
    } else if(magic==FAT_CIGAM_64)
    {
        struct fat_header* fathdr = (struct fat_header*)macho.mutableBytes;
        struct fat_arch_64* archdr = (struct fat_arch_64*)((UInt64)fathdr + sizeof(*fathdr));
        if(NXSwapLong(fathdr->nfat_arch) != 1) {
            return nil;
        }
        
        if(NXSwapLong(archdr->cputype) != CPU_TYPE_ARM64 || archdr->cpusubtype!=0) {
            return nil;
        }
        macho = [NSMutableData dataWithData:
                 [macho subdataWithRange:NSMakeRange(NXSwapLong(archdr->offset), NXSwapLong(archdr->size))]];
        
    } else if(magic != MH_MAGIC_64) {
        return nil;
    }
    
    return macho;
}

NSMutableData* add_hook_section(NSMutableData* macho)
{
    struct mach_header_64* header = (struct mach_header_64*)macho.mutableBytes;
    
    uint64_t vm_end = 0;
    uint64_t min_section_offset = 0;
    struct segment_command_64* linkedit_seg = NULL;
    
    struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *) lc;
            
            if(strcmp(seg->segname,SEG_LINKEDIT)==0)
                linkedit_seg = seg;
            else
            if(seg->vmsize && vm_end<(seg->vmaddr+seg->vmsize))
                vm_end = seg->vmaddr+seg->vmsize;
            
            struct section_64* sec = (struct section_64*)((uint64_t)seg+sizeof(*seg));
            for(int j=0; j<seg->nsects; j++)
            {
                
                if(min_section_offset < sec[j].offset)
                    min_section_offset = sec[j].offset;
            }
        }
        
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(!min_section_offset || !vm_end || !linkedit_seg) {
        return nil;
    }
    
    NSRange linkedit_range = NSMakeRange(linkedit_seg->fileoff, linkedit_seg->filesize);
    NSData* linkedit_data = [macho subdataWithRange:linkedit_range];
    [macho replaceBytesInRange:linkedit_range withBytes:nil length:0];
    
    
    struct segment_command_64 text_seg = {
        .cmd = LC_SEGMENT_64,
        .cmdsize=sizeof(struct segment_command_64)+sizeof(struct section_64),
        .segname = {"__HOOK_TEXT"},
        .vmaddr = vm_end,
        .vmsize = STATIC_HOOK_CODEPAGE_SIZE,
        .fileoff = macho.length,
        .filesize = STATIC_HOOK_CODEPAGE_SIZE,
        .maxprot = VM_PROT_READ|VM_PROT_EXECUTE,
        .initprot = VM_PROT_READ|VM_PROT_EXECUTE,
        .nsects = 1,
        .flags = 0
    };
    struct section_64 text_sec = {
        .segname = {"__HOOK_TEXT"},
        .sectname = {"__hook_text"},
        .addr = text_seg.vmaddr,
        .size = text_seg.vmsize,
        .offset = (uint32_t)text_seg.fileoff,
        .align = 0,
        .reloff = 0,
        .nreloc = 0,
        .flags = S_ATTR_PURE_INSTRUCTIONS|S_ATTR_SOME_INSTRUCTIONS,
        .reserved1 = 0, .reserved2 = 0, .reserved3 = 0
    };
    
    struct segment_command_64 data_seg = {
        .cmd = LC_SEGMENT_64,
        .cmdsize=sizeof(struct segment_command_64)+sizeof(struct section_64),
        .segname = {"__HOOK_DATA"},
        .vmaddr = text_seg.vmaddr+text_seg.vmsize,
        .vmsize = STATIC_HOOK_CODEPAGE_SIZE,
        .fileoff = text_seg.fileoff+text_seg.filesize,
        .filesize = STATIC_HOOK_CODEPAGE_SIZE,
        .maxprot = VM_PROT_READ|VM_PROT_WRITE,
        .initprot = VM_PROT_READ|VM_PROT_WRITE,
        .nsects = 1,
        .flags = 0
    };
    struct section_64 data_sec = {
        .segname = {"__HOOK_DATA"},
        .sectname = {"__hook_data"},
        .addr = data_seg.vmaddr,
        .size = data_seg.vmsize,
        .offset = (uint32_t)data_seg.fileoff,
        .align = 0,
        .reloff = 0,
        .nreloc = 0,
        .flags = 0,
        .reserved1 = 0, .reserved2 = 0, .reserved3 = 0
    };
    
    uint64_t linkedit_cmd_offset = (uint64_t)linkedit_seg - ((uint64_t)header+sizeof(*header));
    unsigned char* cmds = (unsigned char*)malloc(header->sizeofcmds);
    memcpy(cmds, (unsigned char*)header+sizeof(*header), header->sizeofcmds);
    unsigned char* patch = (unsigned char*)header +sizeof(*header) + linkedit_cmd_offset;
    
    memcpy(patch, &text_seg, sizeof(text_seg));
    patch += sizeof(text_seg);
    memcpy(patch, &text_sec, sizeof(text_sec));
    patch += sizeof(text_sec);

    memcpy(patch, &data_seg, sizeof(data_seg));
    patch += sizeof(data_seg);
    memcpy(patch, &data_sec, sizeof(data_sec));
    patch += sizeof(data_sec);
    
    memcpy(patch, cmds+linkedit_cmd_offset, header->sizeofcmds-linkedit_cmd_offset);
    
    linkedit_seg = (struct segment_command_64*)patch;
    
    header->ncmds += 2;
    header->sizeofcmds += text_seg.cmdsize + data_seg.cmdsize;
    
    linkedit_seg->fileoff = macho.length+text_seg.filesize+data_seg.filesize;
    linkedit_seg->vmaddr = vm_end+text_seg.vmsize+data_seg.vmsize;
    
    struct load_command *load_cmd = (struct load_command *)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds;
         i++, load_cmd = (struct load_command *)((uint64_t)load_cmd + load_cmd->cmdsize))
    {
        uint64_t fixoffset = text_seg.filesize+data_seg.filesize;
        
      switch (load_cmd->cmd)
      {
          case LC_DYLD_INFO:
          case LC_DYLD_INFO_ONLY:
          {
            struct dyld_info_command *tmp = (struct dyld_info_command *)load_cmd;
            tmp->rebase_off += fixoffset;
            tmp->bind_off += fixoffset;
            if (tmp->weak_bind_off)
              tmp->weak_bind_off += fixoffset;
            if (tmp->lazy_bind_off)
              tmp->lazy_bind_off += fixoffset;
            if (tmp->export_off)
              tmp->export_off += fixoffset;
          } break;
              
          case LC_SYMTAB:
          {
            struct symtab_command *tmp = (struct symtab_command *)load_cmd;
            if (tmp->symoff)
              tmp->symoff += fixoffset;
            if (tmp->stroff)
              tmp->stroff += fixoffset;
          } break;
              
          case LC_DYSYMTAB:
          {
            struct dysymtab_command *tmp = (struct dysymtab_command *)load_cmd;
            if (tmp->tocoff)
              tmp->tocoff += fixoffset;
            if (tmp->modtaboff)
              tmp->modtaboff += fixoffset;
            if (tmp->extrefsymoff)
              tmp->extrefsymoff += fixoffset;
            if (tmp->indirectsymoff)
              tmp->indirectsymoff += fixoffset;
            if (tmp->extreloff)
              tmp->extreloff += fixoffset;
            if (tmp->locreloff)
              tmp->locreloff += fixoffset;
          } break;
              
          case LC_FUNCTION_STARTS:
          case LC_DATA_IN_CODE:
          case LC_CODE_SIGNATURE:
          case LC_SEGMENT_SPLIT_INFO:
          case LC_DYLIB_CODE_SIGN_DRS:
          case LC_LINKER_OPTIMIZATION_HINT:
          case LC_DYLD_EXPORTS_TRIE:
          case LC_DYLD_CHAINED_FIXUPS:
          {
            struct linkedit_data_command *tmp = (struct linkedit_data_command *)load_cmd;
            if (tmp->dataoff) tmp->dataoff += fixoffset;
          } break;
      }
    }
    
    if(min_section_offset < (sizeof(struct mach_header_64)+header->sizeofcmds)) {
        return nil;
    }
    
    unsigned char* codepage = (unsigned char*)malloc(text_seg.vmsize);
    memset(codepage, 0xFF, text_seg.vmsize);
    [macho appendBytes:codepage length:text_seg.vmsize];
    free(codepage);
    
    unsigned char* datapage = (unsigned char*)malloc(data_seg.vmsize);
    memset(datapage, 0, data_seg.vmsize);
    [macho appendBytes:datapage length:data_seg.vmsize];
    free(datapage);
    
    [macho appendData:linkedit_data];
    
    return macho;
}

bool hex2bytes(char* bytes, unsigned char* buffer)
{
    size_t len=strlen(bytes);
    for(int i=0; i<len; i++) {
        char _byte = bytes[i];
        if(_byte>='0' && _byte<='9')
            _byte -= '0';
        else if(_byte>='a' && _byte<='f')
            _byte -= 'a'-10;
        else if(_byte>='A' && _byte<='F')
            _byte -= 'A'-10;
        else
            return false;
        
        buffer[i/2] &= (i+1)%2 ? 0x0F : 0xF0;
        buffer[i/2] |= _byte << (((i+1)%2)*4);
        
    }
    return true;
}

uint64_t calc_patch_hash(uint64_t vaddr, char* patch)
{
    return [[[NSString stringWithUTF8String:patch] lowercaseString] hash] ^ vaddr;
}


NSString* StaticInlineHookPatch(char* machoPath, uint64_t vaddr, char* patch)
{
    static NSMutableDictionary* gStaticInlineHookMachO = [[NSMutableDictionary alloc] init];
    
    NSString* path = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:[NSString stringWithUTF8String:machoPath]];
        
    NSString* newPath = gStaticInlineHookMachO[path];
    
    NSMutableData* macho=nil;

    if(newPath) {
        macho = load_macho_data(newPath);
        if(!macho) return [NSString stringWithFormat:@"Không tìm thấy File(can't find file):\n Documents/static-inline-hook/%s", machoPath];
    } else {
        macho = load_macho_data(path);
        if(!macho) return [NSString stringWithFormat:@"Không thể đọc file(can't read file):\n.app/%s", machoPath];
    }
    
    uint32_t cryptid = 0;
    struct mach_header_64* header = NULL;
    struct segment_command_64* text_seg = NULL;
    struct segment_command_64* data_seg = NULL;
    
    while(true) {
        
        header = (struct mach_header_64*)macho.mutableBytes;
        
        struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
        for (int i = 0; i < header->ncmds; i++) {
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 * seg = (struct segment_command_64 *) lc;
                if(strcmp(seg->segname,"__HOOK_TEXT")==0)
                    text_seg = seg;
                if(strcmp(seg->segname,"__HOOK_DATA")==0)
                    data_seg = seg;
            }
            if(lc->cmd == LC_ENCRYPTION_INFO_64) {
                struct encryption_info_command_64* info = (struct encryption_info_command_64*)lc;
                if(cryptid==0) cryptid = info->cryptid;
            }
            lc = (struct load_command *) ((char *)lc + lc->cmdsize);
        }
        
        if(text_seg && data_seg) {
            break;
        }
        
        macho = add_hook_section(macho);
        if(!macho) {
            return @"add_hook_section error!";
        }
    }
    
    if(cryptid != 0) {
        return @"Ứng dụng này không được giải mã!!\nthis app is not decrypted!";
    }
    
    if(!text_seg || !data_seg) {
        return @"Không thể phân tích tệp machO!\ncan not parse machO file!";
    }
    
    uint64_t funcRVA = vaddr & ~(4-1);
    void *funcData = rva2data(header, funcRVA);
    
    if(!funcData) {
        return @"Địa chỉ không hợp lệ!\nInvalid offset!";
    }
    
    void* patch_bytes=NULL; uint64_t patch_size=0;
    
    if(patch && patch[0]) {
        uint64_t patch_end = vaddr + (strlen(patch)+1)/2;
        uint64_t code_end = (patch_end+4-1) & ~(4-1);
        
        patch_size = code_end - funcRVA;
        
        NSMutableData* patchBytes = [[NSMutableData alloc] initWithLength:patch_size];
        patch_bytes = patchBytes.mutableBytes;
        
        memcpy(patch_bytes, funcData, patch_size);
        
        if(!hex2bytes(patch, (uint8_t*)patch_bytes+vaddr%4))
            return @"Các byte cần vá không chính xác!\nThe bytes to patch are incorrect!";

    } else if(vaddr % 4) {
        return @"Offset không được căn chỉnh \nThe offset is not aligned!";
    }
    
    
    uint64_t targetRVA = va2rva(header, text_seg->vmaddr);
    void* targetData = rva2data(header, targetRVA);
    
    
    uint64_t InstrumentBridgeRVA = targetRVA;
    
    uint64_t dataRVA = va2rva(header, data_seg->vmaddr);
    void* dataData = rva2data(header, dataRVA);
    
    StaticInlineHookBlock* hookBlock = (StaticInlineHookBlock*)dataData;
    StaticInlineHookBlock* hookBlockRVA = NULL;
    for(int i=0; i<STATIC_HOOK_CODEPAGE_SIZE/sizeof(StaticInlineHookBlock); i++)
    {
        if(hookBlock[i].hook_vaddr==funcRVA)
        {
            if(patch && patch[0] && hookBlock[i].patch_hash!=calc_patch_hash(vaddr, patch))
                return @"The bytes to patch have changed, please revert to original file and try again";
            
            if(newPath)
                return @"Địa chỉ này đã được vá. Vui lòng thay thế tệp đã vá trong thư mục Documents/static-inline-hook của APP thành thư mục .app trong ipa và ký lại bản cài đặt!";
            
            return @"Địa chỉ HOOK đã được vá!\nThe offset to hook is already patched!";
        }
        
        if( funcRVA>hookBlock[i].hook_vaddr &&
           ( funcRVA < (hookBlock[i].hook_vaddr+hookBlock[i].hook_size) || funcRVA < (hookBlock[i].hook_vaddr+hookBlock[i].patch_size) )
          ) {
            return @"Địa chỉ này đã được sử dụng!\nThe offset is occupied!";
        }
        
        if(hookBlock[i].hook_vaddr==0)
        {
            hookBlock = &hookBlock[i];
            hookBlockRVA = (StaticInlineHookBlock*)(dataRVA + i*sizeof(StaticInlineHookBlock));
            
            if(i == 0)
            {
                int codesize = dobby_create_instrument_bridge(targetData);
                
                targetRVA += codesize;
                *(uint64_t*)&targetData += codesize;
            }
            else
            {
                StaticInlineHookBlock* lastBlock = hookBlock - 1;
                targetRVA = lastBlock->code_vaddr + lastBlock->code_size;
                targetData = rva2data(header, targetRVA);
            }
            
            break;
        }
    }
    if(!hookBlockRVA) {
        return @"Đã vượt quá số lượng tối đa có sẵn!\nHOOK count full!";
    }
    
    if(!dobby_static_inline_hook(hookBlock, hookBlockRVA, funcRVA, funcData, targetRVA, targetData,
                                 InstrumentBridgeRVA, patch_bytes, patch_size))
    {
        return @"Địa chỉ không thể được vá!\ncan not patch the offset";
    }
    
    if(patch && patch[0]) {
        hookBlock->patch_size = patch_size;
        hookBlock->patch_hash = calc_patch_hash(vaddr, patch);
    }
    

    NSString* savePath = [NSString stringWithFormat:@"%@/Documents/Va/%s", NSHomeDirectory(), machoPath];
    [NSFileManager.defaultManager createDirectoryAtPath:[NSString stringWithUTF8String:dirname((char*)savePath.UTF8String)] withIntermediateDirectories:YES attributes:nil error:nil];
    
    if(![macho writeToFile:savePath atomically:NO])
        return @"??????!\ncan not write to file!";
    
    gStaticInlineHookMachO[path] = savePath;
    return @"Địa chỉ này chưa được ký. Tệp vá sẽ được tạo trong thư mục Documents/static-inline-hook của APP. Vui lòng thay thế tất cả các tệp trong thư mục này thành thư mục .app trong ipa và ký lại cài đặt.!\nThe offset has not been patched, the patched file will be generated in the Documents/static-inline-hook directory of the APP, please replace all the files in this directory to the .app directory in the ipa and re-sign and reinstall!";
}


void* find_module_by_path(char* machoPath)
{
    NSString* path = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:[NSString stringWithUTF8String:machoPath]];
    
    for(int i=0; i< _dyld_image_count(); i++) {

        const char* fpath = _dyld_get_image_name(i);
        void* baseaddr = (void*)_dyld_get_image_header(i);
        void* slide = (void*)_dyld_get_image_vmaddr_slide(i);
        
        if([path isEqualToString:[NSString stringWithUTF8String:fpath]])
            return baseaddr;
    }
    
    return NULL;
}

StaticInlineHookBlock* find_hook_block(void* base, uint64_t vaddr)
{
    struct segment_command_64* text_seg = NULL;
    struct segment_command_64* data_seg = NULL;
    
    struct mach_header_64* header = (struct mach_header_64*)base;
    
    struct load_command* lc = (struct load_command*)((UInt64)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 * seg = (struct segment_command_64 *) lc;
            if(strcmp(seg->segname,"__HOOK_TEXT")==0)
                text_seg = seg;
            if(strcmp(seg->segname,"__HOOK_DATA")==0)
                data_seg = seg;
        }
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(!text_seg || !data_seg) {
        return NULL;
    }
    
    StaticInlineHookBlock* hookBlock = (StaticInlineHookBlock*)((uint64_t)header + va2rva(header, data_seg->vmaddr));
    for(int i=0; i<STATIC_HOOK_CODEPAGE_SIZE/sizeof(StaticInlineHookBlock); i++)
    {
        if(hookBlock[i].hook_vaddr == (uint64_t)vaddr)
        {
            return &hookBlock[i];
        }
    }
    
    return NULL;
}

void* StaticInlineHookFunction(char* machoPath, uint64_t vaddr, void* replace)
{
    void* base = find_module_by_path(machoPath);
    if(!base) {
        return NULL;
    }
    
    StaticInlineHookBlock* hookBlock = find_hook_block(base, vaddr);
    if(!hookBlock) {
        return NULL;
    }
    
    hookBlock->target_replace = replace;
    return (void*)((uint64_t)base + hookBlock->original_vaddr);
}


BOOL ActiveCodePatch(char* machoPath, uint64_t vaddr, char* patch)
{
    void* base = find_module_by_path(machoPath);
    if(!base) {
        return NO;
    }
    
    StaticInlineHookBlock* hookBlock = find_hook_block(base, vaddr&~3);
    if(!hookBlock) {
        return NO;
    }
    
    if(hookBlock->patch_hash != calc_patch_hash(vaddr, patch)) {
        return NO;
    }
    
    hookBlock->target_replace = (void*)((uint64_t)base + hookBlock->patched_vaddr);
    
    return YES;
}

BOOL DeactiveCodePatch(char* machoPath, uint64_t vaddr, char* patch)
{
    void* base = find_module_by_path(machoPath);
    if(!base) {
        return NO;
    }
    
    StaticInlineHookBlock* hookBlock = find_hook_block(base, vaddr&~3);
    if(!hookBlock) {
        return NO;
    }
    
    if(hookBlock->patch_hash != calc_patch_hash(vaddr, patch)) {
        return NO;
    }
    
    hookBlock->target_replace = NULL;
    
    return YES;
}


#define Hack(x, y, z) \
{ \
    NSString* result_##y = StaticInlineHookPatch(("Frameworks/UnityFramework.framework/UnityFramework"), x, nullptr); \
    if (result_##y) { \
        void* result = StaticInlineHookFunction(("Frameworks/UnityFramework.framework/UnityFramework"), x, (void *) y); \
        *(void **) (&z) = (void*) result; \
    } \
}

/////////////////////////////////////////////////////////////////////////////////////////////

#define kWidth [UIScreen mainScreen].bounds.size.width
#define kHeight [UIScreen mainScreen].bounds.size.height
#define kScale [UIScreen mainScreen].scale



using namespace IL2Cpp;
@interface ImGuiDrawView () <MTKViewDelegate>
@property (nonatomic, strong) id <MTLDevice> device;
@property (nonatomic, strong) id <MTLCommandQueue> commandQueue;
@end

UIView *view;
NSString *jail;
NSString *namedv;
NSString *deviceType;
NSString *bundle;
NSString *ver;

NSUserDefaults *saveSetting = [NSUserDefaults standardUserDefaults];
NSFileManager *fileManager1 = [NSFileManager defaultManager];
NSString *documentDir1 = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) objectAtIndex:0];

static float tabContentOffsetY[5] = {20.0f, 20.0f, 20.0f, 20.0f, 20.0f}; 
static float tabContentAlpha[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f}; 
static int selectedTab = 0;
static int lastSelectedTab = -1; 

const float TAB_CONTENT_ANIMATION_SPEED = 8.0f;
const float BUTTON_WIDTH = 105.0f;
const float BUTTON_HEIGHT = 33.0f;

void AnimateTabContent(int index, bool isActive) {
    if (isActive) {
        if (tabContentOffsetY[index] > 0.0f) {
            tabContentOffsetY[index] -= ImGui::GetIO().DeltaTime * TAB_CONTENT_ANIMATION_SPEED * 20.0f;
            if (tabContentOffsetY[index] < 0.0f) {
                tabContentOffsetY[index] = 0.0f;
            }
        }
        if (tabContentAlpha[index] < 1.0f) {
            tabContentAlpha[index] += ImGui::GetIO().DeltaTime * TAB_CONTENT_ANIMATION_SPEED;
            if (tabContentAlpha[index] > 1.0f) {
                tabContentAlpha[index] = 1.0f;
            }
        }
    } else {
        if (tabContentOffsetY[index] < 20.0f) {
            tabContentOffsetY[index] += ImGui::GetIO().DeltaTime * TAB_CONTENT_ANIMATION_SPEED * 20.0f;
            if (tabContentOffsetY[index] > 20.0f) {
                tabContentOffsetY[index] = 20.0f;
            }
        }
        if (tabContentAlpha[index] > 0.0f) {
            tabContentAlpha[index] -= ImGui::GetIO().DeltaTime * TAB_CONTENT_ANIMATION_SPEED;
            if (tabContentAlpha[index] < 0.0f) {
                tabContentAlpha[index] = 0.0f;
            }
        }
    }
}

@implementation ImGuiDrawView

ImFont* _espFont;
ImFont *_iconFont;

NSMutableDictionary *heroTextures;


    static bool MenDeal = false;
    static bool StreamerMode = false;
    static bool Drawicon = false;
    static bool showMinimap = true;

    int minimapType = 1;
    int skillCDStyle = 2;
uintptr_t botro;
uintptr_t c1;
uintptr_t c2;
uintptr_t c3;
bool showcd = false;
bool ESPEnable;
bool PlayerLine;
bool PlayerBox;
bool PlayerHealth;
bool PlayerName;
bool PlayerDistance;
bool PlayerAlert;
bool ESPArrow;


uint64_t OnClickSelectHeroSkinOffset;
uint64_t IsCanUseSkinOffset;
uint64_t GetHeroWearSkinIdOffset;
uint64_t IsHaveHeroSkinOffset;
uint64_t unpackOffset;

uint64_t actorlink_updateoffset;
uint64_t hackmapoffset;
uint64_t camoffset;
uint64_t updateoffset;
uint64_t oncamoffset;
uint64_t updatelogicoffset;
uint64_t skilldirectoffset;

bool lockcam;
bool hackmap;
bool unlockskin;


bool IgnoreInvisible = false;


uintptr_t (*AsHero)(void *);
monoString* (*_SetPlayerName)(uintptr_t, monoString *, monoString *, bool );

monoString *CreateMonoString(const char *str) {
    monoString *(*String_CreateString)(void *instance, const char *str) = (monoString *(*)(void *, const char *))GetMethodOffset(oxorany("mscorlib.dll"), oxorany("System"), oxorany("String"), oxorany("CreateString"), 1);
    return String_CreateString(NULL, str);
}
void (*old_ActorLinker_Update)(void *instance);
void ActorLinker_Update(void *instance) {
    if (instance != NULL) {
        uintptr_t SkillControl = AsHero(instance);
        uintptr_t HudControl = *(uintptr_t *) ((uintptr_t)instance + 0x78);
        if (showcd) {
        if (HudControl > 0 && SkillControl > 0) {
            uintptr_t Skill1Cd = *(int *)(SkillControl + (c1 - 0x4)) / 1000;
            uintptr_t Skill2Cd = *(int *)(SkillControl + (c2 - 0x4)) / 1000;
            uintptr_t Skill3Cd = *(int *)(SkillControl + (c3 - 0x4)) / 1000;
            uintptr_t Skill4Cd = *(int *)(SkillControl + (botro - 0x4)) / 1000;
            string sk1, sk2, sk3, sk4;
            

            sk1 = (Skill1Cd == 0) ? " ( H ) " : " [" + to_string(Skill1Cd) + "] ";
            sk2 = (Skill2Cd == 0) ? " ( A ) " : " [" + to_string(Skill2Cd) + "] ";
            sk3 = (Skill3Cd == 0) ? " ( T ) " : " [" + to_string(Skill3Cd) + "] ";
            sk4 = (Skill4Cd == 0) ? " ( P ) " : " [" + to_string(Skill4Cd) + "] ";

            string ShowSkill = sk1 + sk2 + sk3; 
            string ShowSkill2 = sk4;
            const char *str1 = ShowSkill.c_str();
            const char *str2 = ShowSkill2.c_str();

            
            monoString* playerName = CreateMonoString(str1);
            monoString* prefixName = CreateMonoString(str2);
            _SetPlayerName(HudControl, playerName, prefixName, true);
            }
        }
        old_ActorLinker_Update(instance);
        
    }
}





int dem(int num){
    int div=1, num1 = num;
    while (num1 != 0) {
        num1=num1/10;
        div=div*10;
    }
    return div;
}

Vector3 VInt2Vector(VInt3 location, VInt3 forward){
    return Vector3((float)(location.X*dem(forward.X)+forward.X)/(1000*dem(forward.X)), (float)(location.Y*dem(forward.Y)+forward.Y)/(1000*dem(forward.Y)), (float)(location.Z*dem(forward.Z)+forward.Z)/(1000*dem(forward.Z)));
}




void ShowContactInfo() {
    ImGui::TextColored(ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.5f), localizedStrings[LocalizedStringKey::Contact].c_str());
    ImGui::Text(localizedStrings[LocalizedStringKey::Telegram].c_str());
    ImGui::Text(localizedStrings[LocalizedStringKey::Admin].c_str());
}

void ShowHackInfo() {
    ImGui::TextColored(ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.5f), localizedStrings[LocalizedStringKey::HackInformation].c_str());
    ImGui::Text(localizedStrings[LocalizedStringKey::HackName].c_str());
    ImGui::Text(localizedStrings[LocalizedStringKey::Version].c_str());
    ImGui::Text(localizedStrings[LocalizedStringKey::Features].c_str());
}

void ShowAdvertisement() {
    ImGui::TextColored(ImVec4(205.0f / 255.0f, 250.0f / 255.0f, 0.0f / 255.0f, 1.5f), localizedStrings[LocalizedStringKey::Advertisement].c_str());
    ImGui::Text(localizedStrings[LocalizedStringKey::BuyServerKey].c_str());
}


- (instancetype)initWithNibName:(nullable NSString *)nibNameOrNil bundle:(nullable NSBundle *)nibBundleOrNil
{

    [self cc];

    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];

    _device = MTLCreateSystemDefaultDevice();
    _commandQueue = [_device newCommandQueue];

    if (!self.device) abort();

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();

    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowPadding = ImVec2(10, 10);
    style.WindowRounding = 5.0f;
    style.FramePadding = ImVec2(5, 5);
    style.FrameRounding = 4.0f;
    style.ItemSpacing = ImVec2(12, 8);
    style.ItemInnerSpacing = ImVec2(8, 6);
    style.IndentSpacing = 25.0f;
    style.ScrollbarSize = 15.0f;
    style.ScrollbarRounding = 9.0f;
    style.GrabMinSize = 5.0f;
    style.GrabRounding = 3.0f;
    style.WindowBorderSize = 0.0f;
    style.FrameBorderSize = 1.0f;
    style.PopupBorderSize = 1.0f;
    style.Alpha = 1.0f;

    ImVec4* colors = ImGui::GetStyle().Colors;
    colors[ImGuiCol_Text]                   = ImVec4(0.95f, 0.96f, 0.98f, 1.00f);
    colors[ImGuiCol_TextDisabled]           = ImVec4(0.36f, 0.42f, 0.47f, 1.00f);
    colors[ImGuiCol_WindowBg]               = ImVec4(0.11f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_ChildBg]                = ImVec4(0.15f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_PopupBg]                = ImVec4(0.08f, 0.08f, 0.08f, 0.94f);
    colors[ImGuiCol_Border]                 = ImVec4(0.08f, 0.10f, 0.12f, 1.00f);
    colors[ImGuiCol_BorderShadow]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]                = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]         = ImVec4(0.12f, 0.20f, 0.28f, 1.00f);
    colors[ImGuiCol_FrameBgActive]          = ImVec4(0.09f, 0.12f, 0.14f, 1.00f);
    colors[ImGuiCol_TitleBg]                = ImVec4(0.09f, 0.12f, 0.14f, 0.65f);
    colors[ImGuiCol_TitleBgActive]          = ImVec4(0.08f, 0.10f, 0.12f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]       = ImVec4(0.00f, 0.00f, 0.00f, 0.51f);
    colors[ImGuiCol_MenuBarBg]              = ImVec4(0.15f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]            = ImVec4(0.02f, 0.02f, 0.02f, 0.39f);
    colors[ImGuiCol_ScrollbarGrab]          = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered]   = ImVec4(0.18f, 0.22f, 0.25f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]    = ImVec4(0.09f, 0.21f, 0.31f, 1.00f);
    colors[ImGuiCol_CheckMark]              = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_SliderGrab]             = ImVec4(0.24f, 0.52f, 0.88f, 1.00f);
    colors[ImGuiCol_SliderGrabActive]       = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_Button]                 = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_ButtonHovered]          = ImVec4(205.0f/255.0f, 250.0f/255.0f, 0.0f/255.0f, 1.00f);
    colors[ImGuiCol_ButtonActive]           = ImVec4(0.06f, 0.53f, 0.98f, 1.00f);
    colors[ImGuiCol_Header]                 = ImVec4(0.20f, 0.25f, 0.29f, 0.55f);
    colors[ImGuiCol_HeaderHovered]          = ImVec4(0.26f, 0.59f, 0.98f, 0.80f);
    colors[ImGuiCol_HeaderActive]           = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_Separator]              = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_SeparatorHovered]       = ImVec4(0.10f, 0.40f, 0.75f, 0.78f);
    colors[ImGuiCol_SeparatorActive]        = ImVec4(0.10f, 0.40f, 0.75f, 1.00f);
    colors[ImGuiCol_ResizeGrip]             = ImVec4(0.26f, 0.59f, 0.98f, 0.20f);
    colors[ImGuiCol_ResizeGripHovered]      = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
    colors[ImGuiCol_ResizeGripActive]       = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);
    colors[ImGuiCol_Tab]                    = ImVec4(0.11f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_TabHovered]             = ImVec4(0.26f, 0.59f, 0.98f, 0.80f);
    colors[ImGuiCol_TabActive]              = ImVec4(0.20f, 0.25f, 0.29f, 1.00f);
    colors[ImGuiCol_TabUnfocused]           = ImVec4(0.11f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_TabUnfocusedActive]     = ImVec4(0.11f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_PlotLines]              = ImVec4(0.61f, 0.61f, 0.61f, 1.00f);
    colors[ImGuiCol_PlotLinesHovered]       = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
    colors[ImGuiCol_PlotHistogram]          = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
    colors[ImGuiCol_PlotHistogramHovered]   = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
    colors[ImGuiCol_TableHeaderBg]          = ImVec4(0.19f, 0.19f, 0.20f, 1.00f);
    colors[ImGuiCol_TableBorderStrong]      = ImVec4(0.31f, 0.31f, 0.45f, 1.00f);
    colors[ImGuiCol_TableBorderLight]       = ImVec4(0.26f, 0.26f, 0.28f, 1.00f);
    colors[ImGuiCol_TableRowBg]             = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt]          = ImVec4(1.00f, 1.00f, 1.00f, 0.06f);
    colors[ImGuiCol_TextSelectedBg]         = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
    colors[ImGuiCol_DragDropTarget]         = ImVec4(1.00f, 1.00f, 0.00f, 0.90f);
    colors[ImGuiCol_NavHighlight]           = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_NavWindowingHighlight]  = ImVec4(1.00f, 1.00f, 1.00f, 0.70f);
    colors[ImGuiCol_NavWindowingDimBg]      = ImVec4(0.80f, 0.80f, 0.80f, 0.20f);
    colors[ImGuiCol_ModalWindowDimBg]       = ImVec4(0.80f, 0.80f, 0.80f, 0.35f);

    ImFontConfig config;
    ImFontConfig icons_config;
    config.FontDataOwnedByAtlas = false;
    icons_config.MergeMode = true;
    icons_config.PixelSnapH = true;
    icons_config.OversampleH = 2;
    icons_config.OversampleV = 2;

    static const ImWchar icons_ranges[] = { 0xf000, 0xf3ff, 0 };

    NSString *fontPath = nssoxorany("/System/Library/Fonts/Core/AvenirNext.ttc");

    _espFont = io.Fonts->AddFontFromFileTTF(fontPath.UTF8String, 30.f, &config, io.Fonts->GetGlyphRangesVietnamese());

    _iconFont = io.Fonts->AddFontFromMemoryCompressedTTF(font_awesome_data, font_awesome_size, 19.0f, &icons_config, icons_ranges);

    _iconFont->FontSize = 5;
    io.FontGlobalScale = 0.5f;

    ImGui_ImplMetal_Init(_device);

    return self;
}



+ (void)showChange:(BOOL)open
{
    MenDeal = open;
}

+ (BOOL)isMenuShowing {
    return MenDeal;
}

- (MTKView *)mtkView
{
    return (MTKView *)self.view;
}




-(void)cc
{

ver = [[[NSBundle mainBundle] infoDictionary] objectForKey:nssoxorany("CFBundleShortVersionString")];

bundle = [[NSBundle mainBundle] bundleIdentifier];

namedv = [[UIDevice currentDevice] name];
deviceType = [[UIDevice currentDevice] model];

if ([DTTJailbreakDetection isJailbroken]) {
jail = nssoxorany("Jailbroken");

}else{
jail = nssoxorany("Not Jailbroken Or Hidden Jailbreak");

}
}

- (void)loadView
{
    CGFloat w = [UIApplication sharedApplication].windows[0].rootViewController.view.frame.size.width;
    CGFloat h = [UIApplication sharedApplication].windows[0].rootViewController.view.frame.size.height;
    self.view = [[MTKView alloc] initWithFrame:CGRectMake(0, 0, w, h)];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.mtkView.device = self.device;
    if (!self.mtkView.device) {
        return;
    }
    self.mtkView.delegate = self;
    self.mtkView.clearColor = MTLClearColorMake(0, 0, 0, 0);
    self.mtkView.backgroundColor = [UIColor colorWithRed:0 green:0 blue:0 alpha:0];
    self.mtkView.clipsToBounds = YES;

    if ([saveSetting objectForKey:@"hackmap"] != nil) {
        hackmap = [saveSetting boolForKey:@"hackmap"];
        unlockskin = [saveSetting boolForKey:@"unlockskin"];
        PlayerBox = [saveSetting boolForKey:@"PlayerBox"];
        PlayerHealth = [saveSetting boolForKey:@"PlayerHealth"];
        PlayerName = [saveSetting boolForKey:@"PlayerName"];
        PlayerDistance = [saveSetting boolForKey:@"PlayerDistance"];
        PlayerAlert = [saveSetting boolForKey:@"PlayerAlert"];
        Drawicon = [saveSetting boolForKey:@"Drawicon"];
        IgnoreInvisible = [saveSetting boolForKey:@"IgnoreInvisible"];
        AimSkill = [saveSetting boolForKey:@"AimSkill"];
        NSArray *minimapPosArray = [saveSetting objectForKey:@"minimapPos"];
        minimapPos = ImVec2([minimapPosArray[0] floatValue], [minimapPosArray[1] floatValue]);
        minimapRotation = [saveSetting floatForKey:@"minimapRotation"];
        minimapScale = [saveSetting floatForKey:@"minimapScale"];
        iconScale = [saveSetting floatForKey:@"iconScale"];
        tablePosX = [saveSetting floatForKey:@"tablePosX"];
        tablePosY = [saveSetting floatForKey:@"tablePosY"];

    }
    if ([saveSetting objectForKey:@"selectedLanguage"] != nil) {
        currentLanguage = static_cast<Language>([saveSetting integerForKey:@"selectedLanguage"]);
    } else {
        currentLanguage = Language::Vietnamese;
    }
    LoadLanguage(currentLanguage);



}


- (void)drawInMTKView:(MTKView*)view
{

    hideRecordTextfield.secureTextEntry = StreamerMode;

    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize.x = view.bounds.size.width;
    io.DisplaySize.y = view.bounds.size.height;

    CGFloat framebufferScale = view.window.screen.nativeScale ?: UIScreen.mainScreen.nativeScale;
    io.DisplayFramebufferScale = ImVec2(framebufferScale, framebufferScale);
    io.DeltaTime = 1 / float(view.preferredFramesPerSecond ?: 120);
    
    id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
        
        if (MenDeal == true) 
        {
            [self.view setUserInteractionEnabled:YES];
            [self.view.superview setUserInteractionEnabled:YES];
            [menuTouchView setUserInteractionEnabled:YES];
        } 
        else if (MenDeal == false) 
        {
           
            [self.view setUserInteractionEnabled:NO];
            [self.view.superview setUserInteractionEnabled:NO];
            [menuTouchView setUserInteractionEnabled:NO];

        }

Attach();
Il2CppAttachOld();
        MTLRenderPassDescriptor* renderPassDescriptor = view.currentRenderPassDescriptor;
        if (renderPassDescriptor != nil)
        {
            id <MTLRenderCommandEncoder> renderEncoder = [commandBuffer renderCommandEncoderWithDescriptor:renderPassDescriptor];
            [renderEncoder pushDebugGroup:nssoxorany("ImGui Jane")];

            ImGui_ImplMetal_NewFrame(renderPassDescriptor);
            ImGui::NewFrame();
             // Chiều dài, rộng menu
            CGFloat width = 480;
            CGFloat height = 330;
            ImGui::SetNextWindowPos(ImVec2((kWidth - width) / 2, (kHeight - height) / 2), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(width, height), ImGuiCond_FirstUseEver);
            static dispatch_once_t onceToken;
dispatch_once(&onceToken, ^{

    Il2CppMethod& getClass(const char* namespaze, const char* className);
    uint64_t getMethod(const char* methodName, int argsCount);
    
    Il2CppMethod methodAccessSystem("Project_d.dll");
    Il2CppMethod methodAccessSystem2("Project.Plugins_d.dll");
    Il2CppMethod methodAccessRes("AovTdr.dll");

    OnClickSelectHeroSkinOffset = methodAccessSystem.getClass(oxorany("Assets.Scripts.GameSystem"), oxorany("HeroSelectNormalWindow")).getMethod(oxorany("OnClickSelectHeroSkin"), 2); // Unlock skin


    IsCanUseSkinOffset = methodAccessSystem.getClass(oxorany("Assets.Scripts.GameSystem"), oxorany("CRoleInfo")).getMethod(oxorany("IsCanUseSkin"), 2); // Unlock Skin


    GetHeroWearSkinIdOffset = methodAccessSystem.getClass(oxorany("Assets.Scripts.GameSystem"), oxorany("CRoleInfo")).getMethod(oxorany("GetHeroWearSkinId"), 1); // Unlock Skin


    IsHaveHeroSkinOffset = methodAccessSystem.getClass(oxorany("Assets.Scripts.GameSystem"), oxorany("CRoleInfo")).getMethod(oxorany("IsHaveHeroSkin"), 3); // Unlock Skin

    unpackOffset = methodAccessRes.getClass(oxorany("CSProtocol"), oxorany("COMDT_HERO_COMMON_INFO")).getMethod(oxorany("unpack"), 2); // Unlock Skin

    actorlink_updateoffset = methodAccessSystem.getClass(oxorany("Kyrios.Actor"), oxorany("ActorLinker")).getMethod(oxorany("Update"), 0);

    hackmapoffset = methodAccessSystem2.getClass(oxorany("NucleusDrive.Logic"), oxorany("LVActorLinker")).getMethod(oxorany("SetVisible"), 3); // Hack Map

    camoffset = methodAccessSystem.getClass("", oxorany("CameraSystem")).getMethod(oxorany("GetCameraHeightRateValue"), 1); // Cam Kéo

    updateoffset = methodAccessSystem.getClass("", oxorany("CameraSystem")).getMethod(oxorany("Update"), 0); // Cam Kéo

    oncamoffset = methodAccessSystem.getClass("", oxorany("CameraSystem")).getMethod(oxorany("OnCameraHeightChanged"), 0); // Cam Kéo

    updatelogicoffset = methodAccessSystem.getClass(oxorany("Assets.Scripts.GameSystem"), oxorany("CSkillButtonManager")).getMethod(oxorany("UpdateLogic"), 1); // Aim

    skilldirectoffset = methodAccessSystem.getClass(oxorany("Assets.Scripts.GameLogic"), oxorany("SkillControlIndicator")).getMethod(oxorany("GetUseSkillDirection"), 1); // Aim



    AsHero = (uintptr_t(*)(void *)) GetMethodOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorLinker") , oxorany("AsHero"), 0);
    _SetPlayerName = (monoString* (*)(uintptr_t, monoString *, monoString *, bool )) GetMethodOffset("Project_d.dll","Assets.Scripts.GameLogic","HudComponent3D","SetPlayerName",3); 
    old_RefreshHeroPanel = (void (*)(void*, bool, bool, bool)) (Method_Project_d_dll_Assets_Scripts_GameSystem_HeroSelectNormalWindow_RefreshHeroPanel_3); 

    m_isCharging = (uintptr_t)GetFieldOffset(oxorany("Project_d.dll"), oxorany("Assets.Scripts.GameSystem"), oxorany("CSkillButtonManager") , oxorany("m_isCharging"));
	m_currentSkillSlotType = (uintptr_t)GetFieldOffset(oxorany("Project_d.dll"), oxorany("Assets.Scripts.GameSystem"), oxorany("CSkillButtonManager") , oxorany("m_currentSkillSlotType"));
    botro = GetFieldOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("HeroWrapperData"), oxorany("m_skillSlot3Unlock"));
    c1 = GetFieldOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("HeroWrapperData"), oxorany("heroWrapSkillData_2"));
    c2 = GetFieldOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("HeroWrapperData"), oxorany("heroWrapSkillData_3"));
    c3 = GetFieldOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("HeroWrapperData"), oxorany("heroWrapSkillData_4"));


    Hack(actorlink_updateoffset, ActorLinker_Update, old_ActorLinker_Update);                      
    Hack(hackmapoffset, SetVisible, _SetVisible);                                         
    Hack(camoffset, _cam, cam);                                                      
    Hack(updateoffset, _Update, Update);                                                 
    Hack(oncamoffset, _highrate, highrate);                                            
    

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        Hack(updatelogicoffset, UpdateLogic, _UpdateLogic);                                   
        Hack(skilldirectoffset, GetUseSkillDirection, _GetUseSkillDirection);                 

        Hack(unpackOffset, unpack, old_unpack);                                         
        Hack(OnClickSelectHeroSkinOffset, OnClickSelectHeroSkin, old_OnClickSelectHeroSkin);           
        Hack(IsCanUseSkinOffset, IsCanUseSkin, old_IsCanUseSkin);                             
        Hack(GetHeroWearSkinIdOffset, GetHeroWearSkinId, old_GetHeroWearSkinId);                    
        Hack(IsHaveHeroSkinOffset, IsHaveHeroSkin, old_IsHaveHeroSkin);                          

    });


});



            
   if (MenDeal == true) {

    char* Gnam = (char*) [[NSString stringWithFormat:nssoxorany("lqmb version: %@ "), ver] cStringUsingEncoding:NSUTF8StringEncoding];
        ImGui::Begin(Gnam, &MenDeal, ImGuiWindowFlags_NoResize);
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 5.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 2.0f);

            ImGui::PushStyleColor(ImGuiCol_Button, selectedTab == 0 ? ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f) : ImVec4(30 / 255.0f, 30 / 255.0f, 30 / 255.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, selectedTab == 0 ? ImVec4(0, 0, 0, 1.0f) : ImVec4(200 / 255.0f, 200 / 255.0f, 200 / 255.0f, 1.0f));
            
            if  (ImGui::Button(localizedStrings[LocalizedStringKey::MainHack].c_str(), ImVec2(BUTTON_WIDTH, BUTTON_HEIGHT))) {
                selectedTab = 0;
            }
            ImGui::PopStyleColor(4);

            ImGui::SameLine();

            ImGui::PushStyleColor(ImGuiCol_Button, selectedTab == 1 ? ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f) : ImVec4(30 / 255.0f, 30 / 255.0f, 30 / 255.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, selectedTab == 1 ? ImVec4(0, 0, 0, 1.0f) : ImVec4(200 / 255.0f, 200 / 255.0f, 200 / 255.0f, 1.0f));

            if (ImGui::Button(localizedStrings[LocalizedStringKey::Skin].c_str(), ImVec2(BUTTON_WIDTH, BUTTON_HEIGHT))) {
                selectedTab = 1;
            }
            ImGui::PopStyleColor(4);

            ImGui::SameLine();

            ImGui::PushStyleColor(ImGuiCol_Button, selectedTab == 2 ? ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f) : ImVec4(30 / 255.0f, 30 / 255.0f, 30 / 255.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, selectedTab == 2 ? ImVec4(0, 0, 0, 1.0f) : ImVec4(200.0f / 255.0f, 200.0f / 255.0f, 200.0f / 255.0f, 1.0f));

            if (ImGui::Button(localizedStrings[LocalizedStringKey::Esp].c_str(), ImVec2(BUTTON_WIDTH, BUTTON_HEIGHT))) {
                selectedTab = 2;
            }
            ImGui::PopStyleColor(4);

            ImGui::SameLine();

            ImGui::PushStyleColor(ImGuiCol_Button, selectedTab == 3 ? ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f) : ImVec4(30 / 255.0f, 30 / 255.0f, 30 / 255.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(205 / 255.0f, 250 / 255.0f, 0 / 255.0f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_Text, selectedTab == 3 ? ImVec4(0, 0, 0, 1.0f) : ImVec4(200.0f / 255.0f, 200.0f / 255.0f, 200.0f / 255.0f, 1.0f));
            

            

            if (ImGui::Button(localizedStrings[LocalizedStringKey::Info].c_str(), ImVec2(BUTTON_WIDTH, BUTTON_HEIGHT))) {
                selectedTab = 3;
            }
            ImGui::PopStyleColor(3);

            ImGui::PopStyleVar(2);

            
            if (lastSelectedTab != selectedTab) {
               
                for (int i = 0; i < 3; ++i) { 
                    tabContentOffsetY[i] = 20.0f;
                    tabContentAlpha[i] = 0.0f;
                }
                lastSelectedTab = selectedTab;
            }
            AnimateTabContent(selectedTab, true);

            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(12, 8 + tabContentOffsetY[selectedTab]));
            ImGui::PushStyleVar(ImGuiStyleVar_Alpha, tabContentAlpha[selectedTab]);

            if (selectedTab == 0) {
                
                
                ImGui::Spacing();
                ImGui::Checkbox(localizedStrings[LocalizedStringKey::Hackmap].c_str(), &hackmap);
                ImGui::SameLine(140);
                ImGui::Checkbox(localizedStrings[LocalizedStringKey::LockCamera].c_str(), &lockcam);
                ImGui::SameLine(270);
                ImGui::Checkbox(localizedStrings[LocalizedStringKey::StartAIM].c_str(), &AimSkill);
                ImGui::Spacing();
                ImGui::BeginGroupPanel(localizedStrings[LocalizedStringKey::AimFeature].c_str(), ImVec2(205.0f / 255.0f, 250.0f / 255.0f));
                ImGui::Spacing();
                DrawAimbotTab();
                ImGui::Spacing();
                ImGui::EndGroupPanel();
                ImGui::Spacing();
                ImGui::BeginGroupPanel(localizedStrings[LocalizedStringKey::CustomizeYourView].c_str(), ImVec2(205.0f / 255.0f, 250.0f / 255.0f));
                ImGui::Checkbox(localizedStrings[LocalizedStringKey::ShowCD].c_str(), &showcd);
                ImGui::SameLine();
                ImGui::SliderFloat("##camera", &camera, 1, 4);
                ImGui::EndGroupPanel();
                ImGui::SameLine();
                ImGui::SameLine();
                ImGui::Spacing();


                
               
            } else if (selectedTab == 1) {
                ImGui::Spacing();
                ImGui::Checkbox(localizedStrings[LocalizedStringKey::UnlockSkin].c_str(), &unlockskin);

                ImGui::Spacing();

                ImGui::BeginGroupPanel(localizedStrings[LocalizedStringKey::LanguageSetting].c_str(), ImVec2(205.0f / 255.0f, 250.0f / 255.0f));
                ImGui::Spacing();
                const char* languageOptions[] = {
                    localizedStrings[LocalizedStringKey::Vietnamese].c_str(),
                    localizedStrings[LocalizedStringKey::English].c_str()
                    

                };
                static int selectedLanguage = static_cast<int>(currentLanguage);
                ImGui::Combo(localizedStrings[LocalizedStringKey::SelectLanguage].c_str(), &selectedLanguage, languageOptions, IM_ARRAYSIZE(languageOptions));
                
                if (selectedLanguage != static_cast<int>(currentLanguage)) {
                    currentLanguage = static_cast<Language>(selectedLanguage);
                    LoadLanguage(currentLanguage);
                    [saveSetting setInteger:selectedLanguage forKey:@"selectedLanguage"];
                    [saveSetting synchronize];
                }
                ImGui::Spacing();
                ImGui::EndGroupPanel();
                ImGui::Spacing();
                
                ImGui::SameLine();
            ImGui::Spacing();
                ImGui::BeginChild("MoreContent", ImVec2(0, 0), true);
                if (ImGui::Button(localizedStrings[LocalizedStringKey::SaveSetting].c_str())) {
                        [saveSetting setBool:hackmap forKey:@"hackmap"];
                        [saveSetting setBool:unlockskin forKey:@"unlockskin"];
                        [saveSetting setBool:PlayerBox forKey:@"PlayerBox"];
                        [saveSetting setBool:PlayerHealth forKey:@"PlayerHealth"];
                        [saveSetting setBool:PlayerName forKey:@"PlayerName"];
                        [saveSetting setBool:PlayerDistance forKey:@"PlayerDistance"];
                        [saveSetting setBool:PlayerAlert forKey:@"PlayerAlert"];
                        [saveSetting setBool:Drawicon forKey:@"Drawicon"];
                        [saveSetting setBool:IgnoreInvisible forKey:@"IgnoreInvisible"];
                        [saveSetting setBool:AimSkill forKey:@"AimSkill"];

                        NSArray *minimapPosArray = @[@(minimapPos.x), @(minimapPos.y)];
                        [saveSetting setObject:minimapPosArray forKey:@"minimapPos"];
                        [saveSetting setFloat:minimapRotation forKey:@"minimapRotation"];
                        [saveSetting setFloat:minimapScale forKey:@"minimapScale"];
                        [saveSetting setFloat:iconScale forKey:@"iconScale"];
                        [saveSetting setFloat:tablePosX forKey:@"tablePosX"];
                        [saveSetting setFloat:tablePosY forKey:@"tablePosY"];
                        [saveSetting setFloat:tableScale forKey:@"tableScale"];
                        [saveSetting synchronize];
                    }

                    ImGui::SameLine();
                    if (ImGui::Button(localizedStrings[LocalizedStringKey::UseSetting].c_str())) {
                        ESPEnable = [saveSetting boolForKey:@"ESPEnable"];
                        unlockskin = [saveSetting boolForKey:@"unlockskin"];
                        PlayerBox = [saveSetting boolForKey:@"PlayerBox"];
                        PlayerHealth = [saveSetting boolForKey:@"PlayerHealth"];
                        PlayerName = [saveSetting boolForKey:@"PlayerName"];
                        PlayerDistance = [saveSetting boolForKey:@"PlayerDistance"];
                        PlayerAlert = [saveSetting boolForKey:@"PlayerAlert"];
                        Drawicon = [saveSetting boolForKey:@"Drawicon"];
                        IgnoreInvisible = [saveSetting boolForKey:@"IgnoreInvisible"];
                        AimSkill = [saveSetting boolForKey:@"AimSkill"];
                        NSArray *minimapPosArray = [saveSetting objectForKey:@"minimapPos"];
                        minimapPos = ImVec2([minimapPosArray[0] floatValue], [minimapPosArray[1] floatValue]);
                        minimapRotation = [saveSetting floatForKey:@"minimapRotation"];
                        minimapScale = [saveSetting floatForKey:@"minimapScale"];
                        iconScale = [saveSetting floatForKey:@"iconScale"];
                        tablePosX = [saveSetting floatForKey:@"tablePosX"];
                        tablePosY = [saveSetting floatForKey:@"tablePosY"];
                        tableScale = [saveSetting floatForKey:@"tableScale"];
                    }

                    ImGui::SameLine();
                    if (ImGui::Button(localizedStrings[LocalizedStringKey::ResetSetting].c_str())) {
                        hackmap = false;
                        unlockskin = false;
                        PlayerBox = false;
                        PlayerHealth = false;
                        PlayerName = false;
                        PlayerDistance = true;
                        PlayerAlert = false;
                        Drawicon = false;
                        IgnoreInvisible = false;
                        AimSkill = false;
                        minimapPos = ImVec2(45.111f, 32.344f);
                        minimapRotation = -0.7f;
                        iconScale = 1.591f;
                        minimapScale = 1.402f;
                    }
                   ImGui::SameLine(); 
                   ImGui::EndChild();
                ImGui::Spacing();
                
            } else if (selectedTab == 2) {
            
                ImGui::Spacing();
                
                                ImGui::BeginGroupPanel(localizedStrings[LocalizedStringKey::Esp].c_str(), ImVec2(205.0f / 255.0f, 250.0f / 255.0f));
                
                ImGui::Checkbox(localizedStrings[LocalizedStringKey::AnHack].c_str(), &StreamerMode); 


                
                ImGui::Spacing();
                ImGui::EndGroupPanel();
                ImGui::Spacing();
                
            } else if (selectedTab == 3) {
                ImGui::Spacing();
                ImGui::BeginChild("MoreContent", ImVec2(0, 0), true);
            
                ShowContactInfo(); 
                ShowHackInfo(); 
                ShowAdvertisement(); 
                ImGui::EndChild();
                ImGui::Spacing();
            

            } 

            ImGui::PopStyleVar(2);

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::End();
        }
            ImDrawList* draw_list = ImGui::GetBackgroundDrawList();
            DrawESP(draw_list);

            
            ImGui::Render();
            ImDrawData* draw_data = ImGui::GetDrawData();
            ImGui_ImplMetal_RenderDrawData(draw_data, commandBuffer, renderEncoder);

            [renderEncoder popDebugGroup];
            [renderEncoder endEncoding];

            [commandBuffer presentDrawable:view.currentDrawable];
            
        }
        [commandBuffer commit];
}

- (void)mtkView:(MTKView*)view drawableSizeWillChange:(CGSize)size
{
    
}

- (void)updateIOWithTouchEvent:(UIEvent *)event
{
    UITouch *anyTouch = event.allTouches.anyObject;
    CGPoint touchLocation = [anyTouch locationInView:self.view];
    ImGuiIO &io = ImGui::GetIO();
    io.MousePos = ImVec2(touchLocation.x, touchLocation.y);

    BOOL hasActiveTouch = NO;
    for (UITouch *touch in event.allTouches)
    {
        if (touch.phase != UITouchPhaseEnded && touch.phase != UITouchPhaseCancelled)
        {
            hasActiveTouch = YES;
            break;
        }
    }
    io.MouseDown[0] = hasActiveTouch;
}

class Camera {
	public:
        static Camera *get_main() {
        Camera *(*get_main_) () = (Camera *(*)()) GetMethodOffset("UnityEngine.CoreModule.dll", "UnityEngine", "Camera", "get_main", 0);
        
        return get_main_();
    }
    
    Vector3 WorldToScreenPoint(Vector3 position) {
        Vector3 (*WorldToScreenPoint_)(Camera *camera, Vector3 position) = (Vector3 (*)(Camera *, Vector3)) GetMethodOffset("UnityEngine.CoreModule.dll", "UnityEngine", "Camera", "WorldToScreenPoint", 1);
        
        return WorldToScreenPoint_(this, position);
    }

    Vector3 WorldToScreen(Vector3 position) {
        Vector3 (*WorldToViewportPoint_)(Camera* camera, Vector3 position, int eye) = (Vector3 (*)(Camera*, Vector3, int)) GetMethodOffset("UnityEngine.CoreModule.dll", "UnityEngine", "Camera", "WorldToViewportPoint", 2);
        
        return WorldToViewportPoint_(this, position, 2);
}

};


class ValueLinkerComponent {
    public:
        int get_actorHp() {
            int (*get_actorHp_)(ValueLinkerComponent * objLinkerWrapper) = (int (*)(ValueLinkerComponent *))GetMethodOffset("Project_d.dll", "Kyrios.Actor", "ValueLinkerComponent", "get_actorHp", 0);  
            return get_actorHp_(this);
        }

        int get_actorHpTotal() {
            int (*get_actorHpTotal_)(ValueLinkerComponent * objLinkerWrapper) =
                (int (*)(ValueLinkerComponent *))GetMethodOffset("Project_d.dll", "Kyrios.Actor", "ValueLinkerComponent", "get_actorHpTotal", 0);  
            return get_actorHpTotal_(this);
        }
};



class CActorInfo {
    public:
        string *ActorName() {
            return *(string **)((uintptr_t)this + GetFieldOffset(oxorany("Project_d.dll"), oxorany("Assets.Scripts.GameLogic"), oxorany("CActorInfo"), oxorany("ActorName")));
        }

};


class ActorConfig{
	public:
	
	int ConfigID() {
		return *(int *) ((uintptr_t) this + GetFieldOffset(oxorany("Project_d.dll"), oxorany("Assets.Scripts.GameLogic"), oxorany("ActorConfig"), oxorany("ConfigID")));
	}
};

class VActorMovementComponent {
public:
    int get_maxSpeed() {
        int (*get_maxSpeed_)(VActorMovementComponent * component) = (int (*)(VActorMovementComponent *))GetMethodOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("VActorMovementComponent"), oxorany("get_maxSpeed"), 0);
        return get_maxSpeed_(this);
    }
};



class ActorLinker {
    public:
        ValueLinkerComponent *ValueComponent() {
            return *(ValueLinkerComponent **)((uintptr_t)this + GetFieldOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorLinker"), oxorany("ValueComponent")));
        }

        ActorConfig *ObjLinker() {
            return *(ActorConfig **) ((uintptr_t) this + GetFieldOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorLinker"), oxorany("ObjLinker")));
        }
        VActorMovementComponent* MovementComponent() {
            return *(VActorMovementComponent**)((uintptr_t)this + GetFieldOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorLinker"), oxorany("MovementComponent"))); 
        }

        Vector3 get_position() {
            Vector3 (*get_position_)(ActorLinker *linker) = (Vector3 (*)(ActorLinker *)) (GetMethodOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorLinker"), oxorany("get_position"), 0));
            return get_position_(this);
        }
        Quaternion get_rotation() {
            Quaternion (*get_rotation_)(ActorLinker *linker) = (Quaternion (*)(ActorLinker *)) (GetMethodOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorLinker"), oxorany("get_rotation"), 0));
            return get_rotation_(this);
        }
        bool IsHostCamp() {
            bool (*IsHostCamp_)(ActorLinker *linker) = (bool (*)(ActorLinker *)) (GetMethodOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorLinker"), oxorany("IsHostCamp"), 0));
            return IsHostCamp_(this);
        }
        
        bool IsHostPlayer() {
            bool (*IsHostPlayer_)(ActorLinker *linker) = (bool (*)(ActorLinker *)) (GetMethodOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorLinker"), oxorany("IsHostPlayer"), 0));
            return IsHostPlayer_(this);
        }
        bool isMoving() {
            return *(bool *) ((uintptr_t) this + GetFieldOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorLinker"), oxorany("isMoving")));
        }

        Vector3 get_logicMoveForward() {
            Vector3 (*get_logicMoveForward_)(ActorLinker *linker) = (Vector3 (*)(ActorLinker *)) (GetMethodOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorLinker"), oxorany("get_logicMoveForward"), 0));
            return get_logicMoveForward_(this);
        }
        
        bool get_bVisible() {
            bool (*get_bVisible_)(ActorLinker *linker) = (bool (*)(ActorLinker *)) (GetMethodOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorLinker"), oxorany("get_bVisible"), 0));
            return get_bVisible_(this);
        }
        uintptr_t AsHero() {
            uintptr_t (*AsHero_)(ActorLinker *linker) = (uintptr_t (*)(ActorLinker *)) (GetMethodOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorLinker"), oxorany("AsHero"), 0));
            return AsHero_(this);
        }
            
};

class ActorManager {
	public:
	
	List<ActorLinker *> *GetAllHeros() {
		List<ActorLinker *> *(*_GetAllHeros)(ActorManager *actorManager) = (List<ActorLinker *> *(*)(ActorManager *)) (GetMethodOffset(oxorany("Project_d.dll"), oxorany("Kyrios.Actor"), oxorany("ActorManager"), oxorany("GetAllHeros"), 0));
		return _GetAllHeros(this);
	}
};

class KyriosFramework {
	public:
	
	static ActorManager *get_actorManager() {
		auto get_actorManager_ = (ActorManager *(*)()) (GetMethodOffset(oxorany("Project_d.dll"), oxorany("Kyrios"), oxorany("KyriosFramework"), oxorany("get_actorManager"), 0));
		return get_actorManager_();
	}
};

class LActorRoot {
public:


Vector3 _location() {
    VInt3* vint3 = (VInt3*)((uintptr_t)this + 0xC0);
    return Vector3(*vint3); 
}

};

ImDrawList* getDrawList(){
    ImDrawList *drawList;
    drawList = ImGui::GetBackgroundDrawList();
    return drawList;
};
void DrawAimbotTab() {
    static int selectedAimWhen = aimType; 
    static int selecteddraw = drawType; 

    const char* aimWhenOptions[] = {localizedStrings[LocalizedStringKey::LowestHealthPercent].c_str(), localizedStrings[LocalizedStringKey::LowestHealth].c_str(), localizedStrings[LocalizedStringKey::NearestDistance].c_str(), localizedStrings[LocalizedStringKey::ClosestToRay].c_str()};
    ImGui::Combo(localizedStrings[LocalizedStringKey::AimTrigger].c_str(), &selectedAimWhen, aimWhenOptions, IM_ARRAYSIZE(aimWhenOptions));

    ImGui::Spacing();

    const char* drawOptions[] = {localizedStrings[LocalizedStringKey::No].c_str(), localizedStrings[LocalizedStringKey::Always].c_str(), localizedStrings[LocalizedStringKey::WhenWatching].c_str()};
    ImGui::Combo(localizedStrings[LocalizedStringKey::DrawAimedObject].c_str(), &selecteddraw, drawOptions, IM_ARRAYSIZE(drawOptions));

    aimType = selectedAimWhen;
    drawType = selecteddraw;
}

void (*_SetVisible)(void *instance, int camp, bool bVisible, const bool forceSync);
void SetVisible(void *instance, int camp, bool bVisible, const bool forceSync = false) {
    if (instance != NULL && hackmap)
	{
    	if (camp == 1 || camp == 2){ bVisible = true;}
	}
    return _SetVisible(instance, camp, bVisible, forceSync);
}


float camera = 1.9;

float(*cam)(void* _this);
float _cam(void* _this){
    return camera;
    return cam(_this);
}

void (*highrate)(void *instance);
void _highrate(void *instance)
{
    highrate(instance);
}


void (*Update)(void *instance);
void _Update(void *instance)
{
    if(instance!=NULL){
        _highrate(instance);
    }
    if(lockcam){
        return;
    }
    return Update(instance);
}

void(*loggoc)(void *instance);
void _loggoc(void *instance) {
    if(loggoc) {
        exit(0);
        loggoc(instance);
    }
}

struct EntityInfo {
    Vector3 myPos;
	Vector3 enemyPos;
	Vector3 moveForward;
	int ConfigID;
	bool isMoving;
    int currentSpeed; 
};

EntityInfo EnemyTarget;


#include "Utils/Esp.h"

static ImVec2 minimapPos = ImVec2(45.111f, 32.344f);
static float minimapRotation = -0.7f;
static float iconScale = 1.591f;
static float minimapScale = 1.402f;
std::string namereal;


Vector3 RotateVectorByQuaternion(Quaternion q) {
	Vector3 v(0.0f, 0.0f, 1.0f);
    float w = q.w, x = q.x, y = q.y, z = q.z;

    Vector3 u(x, y, z);
    Vector3 cross1 = Vector3::Cross(u, v);
    Vector3 cross2 = Vector3::Cross(u, cross1);
    Vector3 result = v + 2.0f * cross1 * w + 2.0f * cross2;

    return result;
}

float SquaredDistance(Vector3 v, Vector3 o) {
	return (v.x - o.x) * (v.x - o.x) + (v.y - o.y) * (v.y - o.y) + (v.z - o.z) * (v.z - o.z);
}

Vector3 calculateSkillDirection(Vector3 myPosi, Vector3 enemyPosi, bool isMoving, Vector3 moveForward, int currentSpeed) {
    if (isMoving) {
        float distance = Vector3::Distance(myPosi, enemyPosi);
        float bulletTime = distance / (25.0f / 0.44f); 

        enemyPosi += Vector3::Normalized(moveForward) * (currentSpeed / 1000.0f) * bulletTime;
    }

    Vector3 direction = enemyPosi - myPosi;
    direction.Normalize();
    return direction;
}

bool AimSkill;
bool isCharging;
int mode = 0, aimType = 1, drawType = 2, skillSlot;

Vector3 (*_GetUseSkillDirection)(void *instance, bool isTouchUse);
Vector3 GetUseSkillDirection(void *instance, bool isTouchUse) {
    if (instance != NULL && AimSkill && EnemyTarget.ConfigID == 196) {
        if (EnemyTarget.myPos != Vector3::zero() && EnemyTarget.enemyPos != Vector3::zero() && skillSlot == 2) {
            return calculateSkillDirection(
                EnemyTarget.myPos, 
                EnemyTarget.enemyPos, 
                EnemyTarget.isMoving, 
                EnemyTarget.moveForward, 
                EnemyTarget.currentSpeed 
            );
        }
    }
    return _GetUseSkillDirection(instance, isTouchUse);
}

uintptr_t m_isCharging, m_currentSkillSlotType;
bool (*_UpdateLogic)(void *instance, int delta);
bool UpdateLogic(void *instance, int delta){
	if (instance != NULL) {
		isCharging = *(bool *)((uintptr_t)instance + m_isCharging);
		skillSlot = *(int *)((uintptr_t)instance + m_currentSkillSlotType);
	}
	return _UpdateLogic(instance, delta);
}

enum class TdrErrorType {
    TDR_NO_ERROR = 0,
    TDR_ERR_SHORT_BUF_FOR_WRITE = -1,
    TDR_ERR_SHORT_BUF_FOR_READ = -2,
    TDR_ERR_STR_LEN_TOO_BIG = -3,
    TDR_ERR_STR_LEN_TOO_SMALL = -4,
    TDR_ERR_STR_LEN_CONFLICT = -5,
    TDR_ERR_MINUS_REFER_VALUE = -6,
    TDR_ERR_REFER_SURPASS_COUNT = -7,
    TDR_ERR_ARG_IS_NULL = -8,
    TDR_ERR_CUTVER_TOO_SMALL = -9,
    TDR_ERR_CUTVER_CONFILICT = -10,
    TDR_ERR_PARSE_TDRIP_FAILED = -11,
    TDR_ERR_INVALID_TDRIP_VALUE = -12,
    TDR_ERR_INVALID_TDRTIME_VALUE = -13,
    TDR_ERR_INVALID_TDRDATE_VALUE = -14,
    TDR_ERR_INVALID_TDRDATETIME_VALUE = -15,
    TDR_ERR_FUNC_LOCALTIME_FAILED = -16,
    TDR_ERR_INVALID_HEX_STR_LEN = -17,
    TDR_ERR_INVALID_HEX_STR_FORMAT = -18,
    TDR_ERR_INVALID_BUFFER_PARAMETER = -19,
    TDR_ERR_NET_CUTVER_INVALID = -20,
    TDR_ERR_ACCESS_VILOATION_EXCEPTION = -21,
    TDR_ERR_ARGUMENT_NULL_EXCEPTION = -22,
    TDR_ERR_USE_HAVE_NOT_INIT_VARIABLE_ARRAY = -23,
    TDR_ERR_INVALID_FORMAT = -24,
    TDR_ERR_HAVE_NOT_SET_SIZEINFO = -25,
    TDR_ERR_VAR_STRING_LENGTH_CONFILICT = -26,
    TDR_ERR_VAR_ARRAY_CONFLICT = -27,
    TDR_ERR_BAD_TLV_MAGIC = -28,
    TDR_ERR_UNMATCHED_LENGTH = -29,
    TDR_ERR_UNION_SELECTE_FIELD_IS_NULL = -30,
    TDR_ERR_SUSPICIOUS_SELECTOR = -31,
    TDR_ERR_UNKNOWN_TYPE_ID = -32,
    TDR_ERR_LOST_REQUIRED_FIELD = -33,
    TDR_ERR_NULL_ARRAY = -34
};

class TdrReadBuf {
private:
    std::vector<uint8_t> beginPtr;
    int32_t position;
    int32_t length;
    bool isNetEndian;
public:
    bool isUseCache;
};

namespace CSProtocol {
	class COMDT_HERO_COMMON_INFO {
    public:
        uint32_t getdwHeroID() {
			if (this == nullptr) {return 0;}
			return *(uint32_t *)((uint64_t)this + Field_AovTdr_dll_CSProtocol_COMDT_HERO_COMMON_INFO_dwHeroID);
		};
        uint16_t getwSkinID() {
			if (this == nullptr) {return 0;}
			return *(uint16_t *)((uint64_t)this + Field_AovTdr_dll_CSProtocol_COMDT_HERO_COMMON_INFO_wSkinID);
		};
		
		void setdwHeroID(uint32_t dwHeroID) {
			if (this == nullptr) {return;}
			*(uint32_t *)((uint64_t)this + Field_AovTdr_dll_CSProtocol_COMDT_HERO_COMMON_INFO_dwHeroID) = dwHeroID;
		};
        void setwSkinID(uint16_t wSkinID) {
			if (this == nullptr) {return;}
			*(uint16_t *)((uint64_t)this + Field_AovTdr_dll_CSProtocol_COMDT_HERO_COMMON_INFO_wSkinID) = wSkinID;
		};
    };
	
	struct saveData {
        static uint32_t heroId;
        static uint16_t skinId;
		static bool enable;
		static std::vector<std::pair<COMDT_HERO_COMMON_INFO*, uint16_t>> arrayUnpackSkin;
		
        static void setData(uint32_t hId, uint16_t sId) {
            heroId = hId;
            skinId = sId;
        }
		
		static void setEnable(bool eb) {
            enable = eb;
        }
		
        static uint32_t getHeroId() {
            return heroId;
        }

        static uint16_t getSkinId() {
            return skinId;
        }
		
		static bool getEnable() {
            return enable;
        }
		
		static void resetArrayUnpackSkin() {
    		if (!saveData::arrayUnpackSkin.empty()) {
        		for (const auto& skinInfo : saveData::arrayUnpackSkin) {
            		COMDT_HERO_COMMON_INFO* heroInfo = skinInfo.first;
            		uint16_t skinId = skinInfo.second;
			
            		heroInfo->setwSkinID(skinId);
        		}
        		saveData::arrayUnpackSkin.clear();
    		}
		}
    };
	
    uint32_t saveData::heroId = 0;
    uint16_t saveData::skinId = 0;
	bool saveData::enable = false;
	std::vector<std::pair<COMDT_HERO_COMMON_INFO*, uint16_t>> saveData::arrayUnpackSkin;
}

void hook_unpack(CSProtocol::COMDT_HERO_COMMON_INFO* instance) {
	if (!CSProtocol::saveData::enable) {return;}
	if (
	instance->getdwHeroID() == CSProtocol::saveData::heroId
	&& CSProtocol::saveData::heroId != 0
	&& CSProtocol::saveData::skinId != 0
	) {
		CSProtocol::saveData::arrayUnpackSkin.emplace_back(instance, instance->getwSkinID());
		instance->setwSkinID(CSProtocol::saveData::skinId);
	}
}

TdrErrorType (*old_unpack)(CSProtocol::COMDT_HERO_COMMON_INFO* instance, TdrReadBuf& srcBuf, int32_t cutVer);
TdrErrorType unpack(CSProtocol::COMDT_HERO_COMMON_INFO* instance, TdrReadBuf& srcBuf, int32_t cutVer) {

	TdrErrorType result = old_unpack(instance, srcBuf, cutVer);
		if (unlockskin) {
	hook_unpack(instance);
	}
    return result;
}



void (*old_RefreshHeroPanel)(void* instance, bool bForceRefreshAddSkillPanel, bool bRefreshSymbol, bool bRefreshHeroSkill);
void (*old_OnClickSelectHeroSkin)(void *instance, uint32_t heroId, uint32_t skinId);
void OnClickSelectHeroSkin(void *instance, uint32_t heroId, uint32_t skinId) {
	if (unlockskin) {
	if (heroId != 0) {
		old_RefreshHeroPanel(instance, 1, 1, 1);
	}
	}
	old_OnClickSelectHeroSkin(instance, heroId, skinId);
}

bool (*old_IsCanUseSkin)(void *instance, uint32_t heroId, uint32_t skinId);
bool IsCanUseSkin(void *instance, uint32_t heroId, uint32_t skinId) {

	if (unlockskin) {
		if (heroId != 0) {
		CSProtocol::saveData::setData(heroId, skinId);
	}
	return 1;
	}
	return old_IsCanUseSkin(instance, heroId, skinId);

}

uint32_t (*old_GetHeroWearSkinId)(void* instance, uint32_t heroId);
uint32_t GetHeroWearSkinId(void* instance, uint32_t heroId) {

if (unlockskin) {
	CSProtocol::saveData::setEnable(true);
	return CSProtocol::saveData::skinId;
	}
	
	return old_GetHeroWearSkinId(instance, heroId);

}

bool (*old_IsHaveHeroSkin)(uintptr_t heroId, uintptr_t skinId, bool isIncludeTimeLimited);
bool IsHaveHeroSkin(uintptr_t heroId, uintptr_t skinId, bool isIncludeTimeLimited = false) {
if (unlockskin) {
	return 1;
	}
	return old_IsHaveHeroSkin(heroId, skinId, isIncludeTimeLimited);

}



void (*_ShowHeroHpInfo)(void *instance, bool bShow); 
void ShowHeroHpInfo(void *instance, bool bShow) {
    if (instance && unlockskin) {
        CSProtocol::saveData::resetArrayUnpackSkin();
    }

    bShow = true;
    
    return _ShowHeroHpInfo(instance, bShow); 
}

struct CDInfo {
    float iconPosX;
    float iconPosY;
    std::string heroNameStr;
    uintptr_t Skill1Cd;
    uintptr_t Skill2Cd;
    uintptr_t Skill3Cd;
    uintptr_t Skill4Cd;
};




static bool showNameTimer = true;
static float nameTimer = 0.0f;
const float NAME_DISPLAY_DURATION = 2.0f; 
static float tablePosX = 189.0f; 
static float tablePosY = 3.5f;
static float tableScale = 0.761f;
void DrawESP(ImDrawList *draw) {

    
    
    
    
    if (AimSkill)
	{
		Quaternion rotation;
		float minDistance = std::numeric_limits<float>::infinity();
		float minDirection = std::numeric_limits<float>::infinity();
		float minHealth = std::numeric_limits<float>::infinity();
		float minHealth2 = std::numeric_limits<float>::infinity();
		float minHealthPercent = std::numeric_limits<float>::infinity();
		ActorLinker *Entity = nullptr;
		
		ActorManager *get_actorManager = KyriosFramework::get_actorManager();
		if (get_actorManager == nullptr) return;

		List<ActorLinker *> *GetAllHeros = get_actorManager->GetAllHeros();
		if (GetAllHeros == nullptr) return;

		ActorLinker **actorLinkers = (ActorLinker **) GetAllHeros->getItems();

		for (int i = 0; i < GetAllHeros->getSize(); i++)
		{
			ActorLinker *actorLinker = actorLinkers[(i *2) + 1];
			if (actorLinker == nullptr) continue;
		
			if (actorLinker->IsHostPlayer()) {
				rotation = actorLinker->get_rotation();
				EnemyTarget.myPos = actorLinker->get_position();
				EnemyTarget.ConfigID = actorLinker->ObjLinker()->ConfigID();
			}
		
			if (actorLinker->IsHostCamp() || !actorLinker->get_bVisible() || actorLinker->ValueComponent()->get_actorHp() < 1) continue;
		
			Vector3 EnemyPos = actorLinker->get_position();
			float Health = actorLinker->ValueComponent()->get_actorHp();
			float MaxHealth = actorLinker->ValueComponent()->get_actorHpTotal();
			int HealthPercent = (int)std::round((float)Health / MaxHealth * 100);
			float Distance = Vector3::Distance(EnemyTarget.myPos, EnemyPos);
            float Direction = SquaredDistance(
                RotateVectorByQuaternion(rotation), 
                calculateSkillDirection(
                    EnemyTarget.myPos, 
                    EnemyPos, 
                    actorLinker->isMoving(), 
                    actorLinker->get_logicMoveForward(),
                    actorLinker->MovementComponent()->get_maxSpeed() 
                )
            );			
			if (Distance < 25.f)
			{
				if (aimType == 0)
				{
					if (HealthPercent < minHealthPercent)
					{
						Entity = actorLinker;
						minHealthPercent = HealthPercent;
					}
				
					if (HealthPercent == minHealthPercent && Health < minHealth2)
					{
						Entity = actorLinker;
						minHealth2 = Health;
						minHealthPercent = HealthPercent;
					}
				}
			
				if (aimType == 1 && Health < minHealth)
				{
					Entity = actorLinker;
					minHealth = Health;
				}
				
				if (aimType == 2 && Distance < minDistance)
				{
					Entity = actorLinker;
					minDistance = Distance;
				}
			
				if (aimType == 3 && Direction < minDirection && isCharging)
				{
					Entity = actorLinker;
					minDirection = Direction;
				}
			}
		}
		if (Entity == nullptr) {
            EnemyTarget.enemyPos = Vector3::zero();
            EnemyTarget.moveForward = Vector3::zero();
            EnemyTarget.ConfigID = 0;
            EnemyTarget.isMoving = false;
        }
		if (Entity != NULL)
		{
			float nDistance = Vector3::Distance(EnemyTarget.myPos, Entity->get_position());
			if (nDistance > 25.f || Entity->ValueComponent()->get_actorHp() < 1)
			{
				EnemyTarget.enemyPos = Vector3::zero();
				EnemyTarget.moveForward = Vector3::zero();
				minDistance = std::numeric_limits<float>::infinity();
				minDirection = std::numeric_limits<float>::infinity();
				minHealth = std::numeric_limits<float>::infinity();
				minHealth2 = std::numeric_limits<float>::infinity();
				minHealthPercent = std::numeric_limits<float>::infinity();
				Entity = nullptr;
			}
					
			else
			{
				EnemyTarget.enemyPos =  Entity->get_position();
				EnemyTarget.moveForward = Entity->get_logicMoveForward();
				EnemyTarget.isMoving = Entity->isMoving();
                EnemyTarget.currentSpeed = Entity->MovementComponent()->get_maxSpeed();
			}
		}
		
		if (Entity != NULL && aimType == 3 && !isCharging)
		{
			EnemyTarget.enemyPos = Vector3::zero();
			EnemyTarget.moveForward = Vector3::zero();
			minDirection = std::numeric_limits<float>::infinity();
			Entity = nullptr;
		}
		
		if ((Entity != NULL || EnemyTarget.enemyPos != Vector3::zero()) && get_actorManager == nullptr)
		{
			EnemyTarget.enemyPos = Vector3::zero();
			EnemyTarget.moveForward = Vector3::zero();
			minDistance = std::numeric_limits<float>::infinity();
			minDirection = std::numeric_limits<float>::infinity();
			minHealth = std::numeric_limits<float>::infinity();
			minHealth2 = std::numeric_limits<float>::infinity();
			minHealthPercent = std::numeric_limits<float>::infinity();
			Entity = nullptr;
		}
		
		if (drawType != 0 && EnemyTarget.ConfigID == 196) {
                if (EnemyTarget.myPos != Vector3::zero() && EnemyTarget.enemyPos != Vector3::zero()) {
                    Vector3 futureEnemyPos = EnemyTarget.enemyPos;
                    if (EnemyTarget.isMoving) {
                        float distance = Vector3::Distance(EnemyTarget.myPos, EnemyTarget.enemyPos);
                        float bulletTime = distance / (25.0f / 0.45f); // Giữ nguyên logic tính bulletTime của bạn
                        futureEnemyPos += Vector3::Normalized(EnemyTarget.moveForward) * (EnemyTarget.currentSpeed / 1000.0f) * bulletTime;
                    }
                    Vector3 EnemySC = Camera::get_main()->WorldToScreen(futureEnemyPos);

                    Vector2 RootVec2 = Vector2(EnemySC.x, EnemySC.y);

                    if (EnemySC.z > 0) {
                        RootVec2 = Vector2(EnemySC.x*kWidth,kHeight -EnemySC.y*kHeight);
                        ImVec2 imRootVec2 = ImVec2(RootVec2.x, RootVec2.y);
                        ImVec2 startLine = ImVec2(kWidth / 2, kHeight / 2);

                        if (drawType == 1) {
                            draw->AddLine(startLine, imRootVec2, ImColor(0, 255, 0, 255), 1.7f); 
                        }
                        if (drawType == 2 && isCharging && skillSlot == 2) {
                            draw->AddLine(startLine, imRootVec2, ImColor(0, 255, 0, 255), 1.0f); 
                        }
                    } else {
                        RootVec2 = Vector2(kWidth - EnemySC.x*kWidth,EnemySC.y*kHeight);
                        ImVec2 imRootVec2 = ImVec2(RootVec2.x, RootVec2.y);
                        ImVec2 startLine = ImVec2(kWidth / 2, kHeight / 2);

                        if (drawType == 1) {
                                draw->AddLine(startLine, imRootVec2, ImColor(0, 255, 0, 255), 1.7f);   
                        }
                        if (drawType == 2 && isCharging && skillSlot == 2) {
                                draw->AddLine(startLine, imRootVec2, ImColor(0, 255, 0, 255), 1.0f); 
                        }
                    }

                    
                    }
            }

		
	}

	
}                                                     






@end