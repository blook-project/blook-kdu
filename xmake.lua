-- blook-kdu: self-contained Windows kernel driver exploitation toolkit.
--
-- Targets
--   kdu_base            static  core utilities (win32, services, PE, traces)
--   kdu_exploit_common  static  shared exploit plumbing (base class, access)
--   kdu_exploit_<n>     static  one target per exploit (independent translation
--                               units, own embedded driver data)
--   kdu_exploits        static  registry that references every exploit
--   kdu_loader          static  manual mapper (stage-1 bootstrap + PE staging)
--   kdu_ipc             static  blook-kchannel adapter (+ kchannel source drop)
--   kdu_payload         binary  kernel payload driver (manual-mapped, WDK)
--   kdu_sdk             static  public SDK implementation (include/blook/kdu)
--   kdu                 binary  the CLI
--   kdu_tests                  host unit tests (doctest)
--   kdu_exploit_test_<n>       per-exploit unit tests (one binary per exploit)
--
-- Options
--   --kchannel_dir=<dir>   blook-kchannel checkout (required for payload/IPC)
--   --build_tests=y|n      build host unit tests (default: y)
--
-- WDK: pass the Windows Kits root with xmake's built-in option,
--   xmake f -y --wdk="C:/path/to/Kits/10"
-- (the WDK NuGet package layout, e.g. %RUNNER_TEMP%/wdk/c, works too).
--
-- blook-kchannel is consumed as a source drop (upstream docs/integration.md):
--   user   : src/user/*.cpp   + src/common/*.cpp
--   kernel : src/kernel/*.cpp + src/common/*.cpp
-- CI pins KCHANNEL_COMMIT and fails if the checkout is missing; a local build
-- without it still works for the exploit unit tests (payload/IPC are skipped).

add_rules("mode.debug", "mode.release")
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})
set_encodings("utf-8")
set_warnings("more")
set_languages("cxx20")
set_version("0.1.0")  -- keep in sync with version.txt / include/blook/kdu/version.h

option("kchannel_dir")
    set_showmenu(true)
    set_description("blook-kchannel checkout (payload + IPC source drop)")
option_end()
option("build_tests")
    set_showmenu(true)
    set_default(true)
    set_description("Build host unit tests")
option_end()

local kchannel_dir = get_config("kchannel_dir")
if not kchannel_dir then
    local local_kchannel = path.join(os.projectdir(), "..", "blook-kchannel")
    if os.isfile(path.join(local_kchannel, "include", "blook", "kchannel.h")) then
        kchannel_dir = local_kchannel
    end
end
local has_kchannel = kchannel_dir ~= nil and
                     os.isfile(path.join(kchannel_dir, "include", "blook",
                                         "kchannel.h"))
local has_kchannel_user = has_kchannel and
                          #os.files(path.join(kchannel_dir, "src", "user",
                                             "*.cpp")) > 0
local has_kchannel_kernel = has_kchannel and
                            #os.files(path.join(kchannel_dir, "src", "kernel",
                                                "*.cpp")) > 0
local build_payload = has_kchannel_kernel and is_plat("windows")
local build_tests = get_config("build_tests") ~= false

if not has_kchannel then
    print("warning: blook-kchannel sources not found; the payload, IPC, SDK " ..
          "and CLI targets are skipped (pass --kchannel_dir=<checkout>)")
elseif not has_kchannel_user or not has_kchannel_kernel then
    print("warning: blook-kchannel checkout is incomplete; payload/IPC " ..
          "targets are skipped")
end

add_requires("fmt", "spdlog", "nlohmann_json")
add_requires("cli11")
add_requires("doctest")

-- Builder calls below apply to the current target in this file.
local function kdu_user_defaults()
    set_encodings("utf-8")
    set_languages("cxx20")
    add_defines("UNICODE", "NOMINMAX", "WIN32_LEAN_AND_MEAN",
                "_CRT_SECURE_NO_WARNINGS")
    add_includedirs("include", "src", {public = true})
    add_syslinks("advapi32", "user32", "shell32", "psapi", "ntdll", "version",
                 "ole32", "crypt32", "wintrust", "bcrypt", "wevtapi")
    if has_kchannel_user then
        add_includedirs(path.join(kchannel_dir, "include"))
        add_defines("KDU_HAS_KCHANNEL=1")
    end
end

-- ---------------------------------------------------------------------------
-- core utilities
-- ---------------------------------------------------------------------------
target("kdu_base")
    set_kind("static")
    kdu_user_defaults()
    add_files("src/core/*.cpp")
    add_packages("fmt", "spdlog")

-- ---------------------------------------------------------------------------
-- shared exploit plumbing
-- ---------------------------------------------------------------------------
target("kdu_exploit_common")
    set_kind("static")
    kdu_user_defaults()
    add_files("src/exploits/common/*.cpp")
    add_deps("kdu_base")
    add_packages("fmt", "spdlog")

-- ---------------------------------------------------------------------------
-- exploits: one static library per exploit directory
-- ---------------------------------------------------------------------------
local exploit_names = {}
for _, dir in ipairs(os.dirs("src/exploits/*")) do
    local name = path.basename(dir)
    if name ~= "common" and name ~= "data" and
       #os.files(path.join(dir, "*.cpp")) > 0 then
        table.insert(exploit_names, name)
    end
end
table.sort(exploit_names)

for _, name in ipairs(exploit_names) do
    target("kdu_exploit_" .. name)
        set_kind("static")
        kdu_user_defaults()
        add_files("src/exploits/" .. name .. "/*.cpp")
        add_deps("kdu_base", "kdu_exploit_common")
        add_packages("fmt", "spdlog")
end

target("kdu_exploits")
    set_kind("static")
    kdu_user_defaults()
    add_files("src/exploits/registry.cpp")
    add_deps("kdu_base", "kdu_exploit_common")
    for _, name in ipairs(exploit_names) do
        add_deps("kdu_exploit_" .. name)
    end
    add_packages("fmt", "spdlog")

-- ---------------------------------------------------------------------------
-- kernel stage image (tiny WDK driver mapped into a victim driver's .text)
-- ---------------------------------------------------------------------------
if build_payload then
    target("kdu_stage")
        set_kind("binary")
        add_rules("wdk.driver", "wdk.env.wdm")
        add_files("src/loader/stage/*.cpp")
        add_includedirs("src", "src/loader")
        add_defines("UNICODE", "NOMINMAX", "_KERNEL_MODE=1",
                    "NTDDI_VERSION=0x0A00000C")
        add_syslinks("ntoskrnl", "wdmsec")
        add_cxflags("/GS-", "/GR-", "/W4", {force = true})
        add_ldflags("/ENTRY:kdu_stage_entry", {force = true})
        after_build(function (target)
            local script = path.join(os.projectdir(), "scripts",
                                     "gen-payload-blob.ps1")
            local output = path.join(os.projectdir(), "build", "generated",
                                     "stage_blob.h")
            os.exec('pwsh -NoProfile -ExecutionPolicy Bypass -File "' ..
                    script .. '" -InputFile "' .. target:targetfile() ..
                    '" -OutputFile "' .. output ..
                    '" -Symbol kdu_stage_image')
        end)
end

-- ---------------------------------------------------------------------------
-- manual mapper
-- ---------------------------------------------------------------------------
target("kdu_loader")
    set_kind("static")
    kdu_user_defaults()
    add_files("src/loader/*.cpp")
    add_includedirs(path.join(os.projectdir(), "build", "generated"))
    add_deps("kdu_base")
    if build_payload then
        add_deps("kdu_stage")
    end
    add_packages("fmt", "spdlog")

-- ---------------------------------------------------------------------------
-- IPC (blook-kchannel adapter) + kernel payload
-- ---------------------------------------------------------------------------
if has_kchannel_user then
    target("kdu_ipc")
        set_kind("static")
        kdu_user_defaults()
        add_files("src/ipc/*.cpp")
        add_deps("kdu_base")
        add_packages("fmt", "spdlog")
        add_includedirs(path.join(kchannel_dir, "src"),
                        path.join(os.projectdir(), "build", "generated"))
        add_files(path.join(kchannel_dir, "src", "user", "*.cpp"),
                  path.join(kchannel_dir, "src", "common", "*.cpp"))
        if build_payload then
            -- payload blob header is generated by the payload after_build step
            add_deps("kdu_payload")
        end
end

if build_payload then
    target("kdu_payload")
        set_kind("binary")
        add_rules("wdk.driver", "wdk.env.wdm")
        add_files("src/payload/*.cpp")
        add_includedirs("src/payload", "src", path.join(kchannel_dir, "include"),
                        path.join(kchannel_dir, "src"))
        add_files(path.join(kchannel_dir, "src", "kernel", "*.cpp"),
                  path.join(kchannel_dir, "src", "common", "*.cpp"))
        add_defines("UNICODE", "NOMINMAX", "_KERNEL_MODE=1",
                    "KDU_HAS_KCHANNEL=1",
                    -- ExAllocatePool2 (used by kchannel) needs 2004+ headers
                    "NTDDI_VERSION=0x0A00000C")
        add_syslinks("ntoskrnl", "wdmsec")
        local compat = path.join(os.projectdir(), "src", "payload",
                                 "kdu_kernel_compat.h")
        add_cxflags("/GS-", "/GR-", "/W4", "/FI" .. compat, {force = true})
        add_ldflags("/ENTRY:kdu_payload_entry", {force = true})
        -- After the .sys is linked, turn it into a C array header so the CLI
        -- can carry the payload inside its own image (single self-contained exe).
        after_build(function (target)
            local script = path.join(os.projectdir(), "scripts",
                                     "gen-payload-blob.ps1")
            local output = path.join(os.projectdir(), "build", "generated",
                                     "payload_blob.h")
            os.exec('pwsh -NoProfile -ExecutionPolicy Bypass -File "' ..
                    script .. '" -InputFile "' .. target:targetfile() ..
                    '" -OutputFile "' .. output .. '"')
        end)
end

-- ---------------------------------------------------------------------------
-- e2e assets (guest test driver + marker process)
-- ---------------------------------------------------------------------------
if build_payload then
    target("kdu_guest_test_driver")
        set_kind("binary")
        add_rules("wdk.driver", "wdk.env.wdm")
        add_files("tests/guest/*.c")
        add_defines("UNICODE", "NOMINMAX", "_KERNEL_MODE=1",
                    "NTDDI_VERSION=0x0A00000C")
        add_cxflags("/W4", {force = true})
end

target("kdu_api_example")
    set_kind("binary")
    kdu_user_defaults()
    add_files("examples/api_example.cpp")
    add_deps("kdu_sdk")

target("kdu_e2e_helper")
    set_kind("binary")
    kdu_user_defaults()
    add_files("tests/e2e/helper.cpp")
    add_deps("kdu_base")
-- ---------------------------------------------------------------------------
-- SDK + CLI (require the IPC adapter, i.e. real kchannel sources)
-- ---------------------------------------------------------------------------
if has_kchannel_user then
    target("kdu_sdk")
        set_kind("static")
        kdu_user_defaults()
        add_files("src/sdk/*.cpp")
        add_deps("kdu_base", "kdu_exploits", "kdu_loader", "kdu_ipc")
        add_packages("fmt", "spdlog")

    target("kdu")
        set_kind("binary")
        kdu_user_defaults()
        add_files("src/cli/*.cpp", "src/cli/commands/*.cpp")
        -- embedded vulnerable drivers (signed RCDATA resources; the table is
        -- generated by scripts/prepare-assets.ps1, which scripts/build.ps1 and
        -- CI run before configuring)
        add_files("src/assets.rc")
        add_deps("kdu_sdk")
        add_packages("cli11", "fmt", "spdlog", "nlohmann_json")
end

-- ---------------------------------------------------------------------------
-- tests
-- ---------------------------------------------------------------------------
if build_tests then
    if has_kchannel_user then
        target("kdu_tests")
            set_kind("binary")
            kdu_user_defaults()
            add_files("tests/unit/main.cpp", "tests/unit/core/*.cpp")
            add_includedirs("tests/unit")
            add_deps("kdu_sdk")
            add_packages("doctest", "fmt", "spdlog")
    end

    -- Per-exploit test binaries are independent of the SDK/IPC; CI runs each
    -- of them as its own job.
    for _, name in ipairs(exploit_names) do
        target("kdu_exploit_test_" .. name)
            set_kind("binary")
            kdu_user_defaults()
            add_files("tests/unit/exploits/main.cpp")
            add_files("tests/unit/exploits/" .. name .. "_test.cpp")
            add_includedirs("tests/unit")
            add_deps("kdu_exploit_" .. name, "kdu_exploit_common", "kdu_base")
            add_packages("doctest", "fmt", "spdlog")
    end
end










