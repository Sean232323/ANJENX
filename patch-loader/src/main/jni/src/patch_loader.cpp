/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2022 LSPosed Contributors
 */

//
// Created by Nullptr on 2022/3/17.
//

#include <stdio.h>         // fopen, fgets, sscanf, FILE, etc.
#include <stdlib.h>        // malloc, free, exit, etc. (optional for memory)
#include <string.h>        // strstr, memcpy, memset
#include <stdint.h>        // uint8_t, uintptr_t
#include <unistd.h>        // close
#include <fcntl.h>         // open, O_RDONLY
#include <sys/mman.h>      // mmap, mremap, munmap, PROT_*, MAP_*
#include <sys/stat.h>      // fstat, struct stat
#include <elf.h>           // Elf64_Ehdr, Elf64_Phdr, PT_LOAD, PF_X

#include "patch_loader.h"

#include "art/runtime/jit/profile_saver.h"
#include "art/runtime/oat_file_manager.h"
#include "elf_util.h"
#include "jni/bypass_sig.h"
#include "native_util.h"
#include "symbol_cache.h"
#include "utils/jni_helper.hpp"

using namespace lsplant;

namespace lspd {

void PatchLoader::LoadDex(JNIEnv* env, Context::PreloadedDex&& dex) {
    auto class_activity_thread = JNI_FindClass(env, "android/app/ActivityThread");
    auto class_activity_thread_app_bind_data =
        JNI_FindClass(env, "android/app/ActivityThread$AppBindData");
    auto class_loaded_apk = JNI_FindClass(env, "android/app/LoadedApk");

    auto mid_current_activity_thread = JNI_GetStaticMethodID(
        env, class_activity_thread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    auto mid_get_classloader =
        JNI_GetMethodID(env, class_loaded_apk, "getClassLoader", "()Ljava/lang/ClassLoader;");
    auto fid_m_bound_application = JNI_GetFieldID(env, class_activity_thread, "mBoundApplication",
                                                  "Landroid/app/ActivityThread$AppBindData;");
    auto fid_info =
        JNI_GetFieldID(env, class_activity_thread_app_bind_data, "info", "Landroid/app/LoadedApk;");

    auto activity_thread =
        JNI_CallStaticObjectMethod(env, class_activity_thread, mid_current_activity_thread);
    auto m_bound_application = JNI_GetObjectField(env, activity_thread, fid_m_bound_application);
    auto info = JNI_GetObjectField(env, m_bound_application, fid_info);
    auto stub_classloader = JNI_CallObjectMethod(env, info, mid_get_classloader);

    if (!stub_classloader) [[unlikely]] {
        LOGE("getStubClassLoader failed!!!");
        return;
    }

    auto in_memory_classloader = JNI_FindClass(env, "dalvik/system/InMemoryDexClassLoader");
    auto mid_init = JNI_GetMethodID(env, in_memory_classloader, "<init>",
                                    "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    auto byte_buffer_class = JNI_FindClass(env, "java/nio/ByteBuffer");
    auto dex_buffer = env->NewDirectByteBuffer(dex.data(), dex.size());
    if (auto my_cl =
            JNI_NewObject(env, in_memory_classloader, mid_init, dex_buffer, stub_classloader)) {
        inject_class_loader_ = JNI_NewGlobalRef(env, my_cl);
    } else {
        LOGE("InMemoryDexClassLoader creation failed!!!");
        return;
    }

    env->DeleteLocalRef(dex_buffer);
}

void PatchLoader::InitArtHooker(JNIEnv* env, const InitInfo& initInfo) {
    Context::InitArtHooker(env, initInfo);
    handler = initInfo;
    art::ProfileSaver::DisableInline(initInfo);
    art::FileManager::DisableBackgroundVerification(initInfo);
}

void PatchLoader::InitHooks(JNIEnv* env) {
    Context::InitHooks(env);
    RegisterBypass(env);
}

void PatchLoader::SetupEntryClass(JNIEnv* env) {
    if (auto entry_class = FindClassFromLoader(env, GetCurrentClassLoader(),
                                               "org.lsposed.lspatch.loader.LSPApplication")) {
        entry_class_ = JNI_NewGlobalRef(env, entry_class);
    }
}

#define PAGE_SIZE 4096

typedef struct {
    void* base;
    size_t size;
} ExecSegment;

// You need to extract the executable segment from memory map
int find_so_exec_segment_in_maps(const char* so_name, ExecSegment* result) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, so_name) && strstr(line, "r-xp")) {
            uintptr_t start, end;
            sscanf(line, "%lx-%lx", &start, &end);
            result->base = (void*)start;
            result->size = end - start;
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}


// Parse ELF headers to find executable PT_LOAD segment
int find_so_exec_segment_from_file(const char* path, ExecSegment* result) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    fstat(fd, &st);
    uint8_t* data = static_cast<uint8_t *>(mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
    if (data == MAP_FAILED) {
        close(fd);
        return -1;
    }

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)data;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(data + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            result->base = data + phdr[i].p_offset;
            result->size = phdr[i].p_filesz;
            close(fd);
            return 0;
        }
    }

    close(fd);
    return -1;
}

int hidden_so_exec_segment(const char* so_path) {
    ExecSegment maps_exec = {0}, file_exec = {0};

    if (find_so_exec_segment_in_maps(so_path, &maps_exec) != 0) {
        LOGD("Cannot find so exec segment in maps\n");
        return -1;
    }

    if (find_so_exec_segment_from_file(so_path, &file_exec) != 0) {
        LOGD("Cannot find exec segment in file\n");
        return -1;
    }

    // Step 1: Copy original exec memory to anonymous region
    void* anon = mmap(NULL, maps_exec.size, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anon == MAP_FAILED) {
        LOGD("mmap anon");
        return -1;
    }

    memcpy(anon, maps_exec.base, maps_exec.size);

    // Step 2: mremap to overwrite original exec region with anon
    void* remapped = mremap(anon, maps_exec.size, maps_exec.size,
                            MREMAP_MAYMOVE | MREMAP_FIXED, maps_exec.base);
    if (remapped == MAP_FAILED) {
        LOGD("mremap");
        return -1;
    }

    LOGD("Mapped anonymous region over original exec segment : %s", so_path);

    // Step 3: open so file to create a fake memory segment with the name
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) {
        LOGD("open");
        return -1;
    }

    void* fake = mmap(NULL, maps_exec.size, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE, fd, 0);
    if (fake == MAP_FAILED) {
        LOGD("mmap fake");
        close(fd);
        return -1;
    }

    close(fd);
    memset(fake, 0, maps_exec.size);

    // Step 4: Copy clean exec segment from file
    memcpy(fake, file_exec.base, file_exec.size);
    mprotect(fake, maps_exec.size, PROT_READ | PROT_EXEC);

    LOGD("Simulated clean exec segment at %p, %s", fake, so_path);

    return 0;
}

void PatchLoader::Load(JNIEnv* env) {
    /* InitSymbolCache(nullptr); */
    lsplant::InitInfo initInfo{
        .inline_hooker =
            [](auto t, auto r) {
                void* bk = nullptr;
                return HookInline(t, r, &bk) == 0 ? bk : nullptr;
            },
        .inline_unhooker = [](auto t) { return UnhookInline(t) == 0; },
        .art_symbol_resolver = [](auto symbol) { return GetArt()->getSymbAddress(symbol); },
        .art_symbol_prefix_resolver =
            [](auto symbol) { return GetArt()->getSymbPrefixFirstAddress(symbol); },
    };

    auto stub = JNI_FindClass(env, "org/lsposed/lspatch/metaloader/LSPAppComponentFactoryStub");
    auto dex_field = JNI_GetStaticFieldID(env, stub, "dex", "[B");

    ScopedLocalRef<jbyteArray> array = JNI_GetStaticObjectField(env, stub, dex_field);
    auto dex = PreloadedDex{env->GetByteArrayElements(array.get(), nullptr),
                            static_cast<size_t>(JNI_GetArrayLength(env, array))};

    hidden_so_exec_segment("/apex/com.android.runtime/lib64/bionic/libc.so");
    hidden_so_exec_segment("/apex/com.android.art/lib64/libart.so");

    InitArtHooker(env, initInfo);
    LoadDex(env, std::move(dex));
    InitHooks(env);

    GetArt(true);

    SetupEntryClass(env);
    FindAndCall(env, "onLoad", "()V");
}
}  // namespace lspd
